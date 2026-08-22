#!/bin/bash
# Ein Agent-Release: hier committen, den OpenWrt-Feed nachziehen, optional
# sofort auf einen Dev-AP rollen.
#
# Der Agent liegt in diesem Repo, gebaut wird er aus dem Paket `apman` im
# Feed-Repo. Das Paket zieht einen FESTEN Commit von hier — dadurch ist jeder
# Build reproduzierbar, aber jede Aenderung am Agent braucht zwei Schritte:
# Commit hier, Bump dort. Genau das macht dieses Skript, damit die beiden nicht
# auseinanderlaufen.
#
#   contrib/release.sh -m "radius: fix xy"          # committen, pushen, feed bumpen
#   contrib/release.sh -m "..." -d ap-av-attic      # dasselbe, danach sofort auf den ap
#   contrib/release.sh -d ap-av-attic --only-dev    # nur ausrollen, nichts committen
#   contrib/release.sh --no-push                    # alles lokal lassen (hash bleibt aus)
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"
FEED_DEFAULT="$(dirname "$ROOT")/ddimension-openwrt-repo"

MSG=""
DEVS=()
FEED="${APMAN_FEED_REPO:-$FEED_DEFAULT}"
PUSH=1
ONLY_DEV=0
FEED_PUSH=0
RUN_TESTS=0

usage() {
	cat <<'EOF'
Usage: contrib/release.sh [optionen]

  -m, --message TEXT     Commit-Nachricht fuer offene Aenderungen in diesem Repo.
                         Ohne -m muss der Baum sauber sein.
  -d, --dev AP           Sofort auf diesen AP ausrollen (mehrfach moeglich).
                         Kopiert genau das, was das Paket installiert, ausser
                         /etc/config/apman (conffile) — und startet neu.
      --only-dev         Nur ausrollen. Kein Commit, kein Feed, kein Push.
      --feed PATH        Pfad zum Feed-Repo (Default: $FEED_DEFAULT,
                         ueberschreibbar mit APMAN_FEED_REPO)
      --feed-push        Auch das Feed-Repo pushen (Default: nur committen)
      --no-push          Diesen Commit nicht pushen. Dann wird KEIN Mirror-Hash
                         berechnet, denn der Build kaeme nicht an den Commit.
      --test             tests/ nach dem Rollout auf dem Dev-AP laufen lassen
  -h, --help

Was der Feed-Bump aendert (apman/Makefile):
  PKG_VERSION          +1  — neuer Tarball-Name, sonst kollidiert der Download-Cache
  PKG_RELEASE          1   — zurueckgesetzt, die Quelle ist neu
  PKG_SOURCE_VERSION   der Commit von hier
  PKG_MIRROR_HASH      sha256 des Tarballs, den OpenWrt daraus bauen wird
EOF
}

while [ $# -gt 0 ]; do
	case "$1" in
		-m|--message) MSG="$2"; shift 2 ;;
		-d|--dev) DEVS+=("$2"); shift 2 ;;
		--only-dev) ONLY_DEV=1; shift ;;
		--feed) FEED="$2"; shift 2 ;;
		--feed-push) FEED_PUSH=1; shift ;;
		--no-push) PUSH=0; shift ;;
		--test) RUN_TESTS=1; shift ;;
		-h|--help) usage; exit 0 ;;
		*) echo "unbekannte option: $1" >&2; usage >&2; exit 2 ;;
	esac
done

say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

# --------------------------------------------------------------------------
# Rollout auf einen AP: dieselbe Dateiliste wie Package/apman/install, ohne
# /etc/config/apman. Das ist ein conffile — es traegt die Identitaet des AP
# (hostname, broker, zertifikate), und es zu ueberschreiben haette den AP
# stillgelegt. Der Keystore unter /etc/apman bleibt ebenfalls unangetastet.
# --------------------------------------------------------------------------
rollout() {
	local ap="$1" changed_collectd=0
	say "rollout auf $ap"
	ssh -o BatchMode=yes "root@$ap" 'mkdir -p /usr/lib/lua /usr/bin /usr/share/collectd /lib/upgrade/keep.d /etc/collectd/conf.d /etc/apman'
	scp -q -o BatchMode=yes \
		"$ROOT"/files/usr/lib/lua/apman.lua \
		"$ROOT"/files/usr/lib/lua/apman-collectd.lua \
		"$ROOT"/files/usr/lib/lua/apman-radius.lua \
		"root@$ap:/usr/lib/lua/"
	scp -q -o BatchMode=yes "$ROOT/files/usr/bin/apman-status"        "root@$ap:/usr/bin/"
	scp -q -o BatchMode=yes "$ROOT/files/etc/init.d/apman-status"     "root@$ap:/etc/init.d/"
	scp -q -o BatchMode=yes "$ROOT/files/lib/upgrade/keep.d/apman"    "root@$ap:/lib/upgrade/keep.d/"
	scp -q -o BatchMode=yes "$ROOT/files/usr/share/collectd/types.apman.db" "root@$ap:/usr/share/collectd/"
	scp -q -o BatchMode=yes "$ROOT/files/etc/collectd/conf.d/lua-apman.conf" "root@$ap:/etc/collectd/conf.d/"
	ssh -o BatchMode=yes "root@$ap" 'chmod 755 /usr/bin/apman-status /etc/init.d/apman-status /usr/lib/lua/apman*.lua'

	# Der Dienst heisst apman-status, nicht apman. Ein `/etc/init.d/apman
	# restart` laeuft ins Leere und man sucht danach lange am falschen Ende.
	say "$ap: apman-status neu starten"
	ssh -o BatchMode=yes "root@$ap" '/etc/init.d/apman-status restart' || true
	sleep 3
	ssh -o BatchMode=yes "root@$ap" '
		pgrep -f apman-status >/dev/null && echo "  laeuft: $(pgrep -f apman-status | tr "\n" " ")" || { echo "  LAEUFT NICHT"; exit 1; }
		logread | grep -a apman-status | tail -5 | sed "s/^/  /"'
	[ "$changed_collectd" = 1 ] && ssh -o BatchMode=yes "root@$ap" '/etc/init.d/collectd restart' || true

	if [ "$RUN_TESTS" = 1 ]; then
		say "$ap: tests"
		for t in "$ROOT"/tests/*.lua; do
			scp -q -o BatchMode=yes "$t" "root@$ap:/tmp/"
			ssh -o BatchMode=yes "root@$ap" "lua /tmp/$(basename "$t")" | sed 's/^/  /'
		done
	fi
}

if [ "$ONLY_DEV" = 1 ]; then
	[ ${#DEVS[@]} -gt 0 ] || { echo "--only-dev braucht -d AP" >&2; exit 2; }
	for ap in "${DEVS[@]}"; do rollout "$ap"; done
	exit 0
fi

# --------------------------------------------------------------------------
# 1. Commit hier
# --------------------------------------------------------------------------
cd "$ROOT"
if [ -n "$(git status --porcelain)" ]; then
	[ -n "$MSG" ] || { echo "offene aenderungen, aber keine -m nachricht" >&2; exit 1; }
	say "commit"
	git add -A
	git commit -q -m "$MSG"
fi
COMMIT="$(git rev-parse HEAD)"
SHORT="$(git rev-parse --short=8 HEAD)"
echo "commit: $COMMIT"

URL="$(git config --get remote.origin.url)"
# Der Feed laedt ueber https, auch wenn hier ssh konfiguriert ist.
HTTPS_URL="$(echo "$URL" | sed -e 's|^git@github.com:|https://github.com/|' -e 's|\.git$||')"

if [ "$PUSH" = 1 ]; then
	say "push"
	git push origin HEAD
else
	echo "kein push — der feed-bump wird uebersprungen, weil der build den commit nicht faende"
	for ap in "${DEVS[@]:-}"; do [ -n "$ap" ] && rollout "$ap"; done
	exit 0
fi

# --------------------------------------------------------------------------
# 2. Mirror-Hash
#
# OpenWrt laedt PKG_SOURCE_PROTO:=git ueber DownloadMethod/rawgit und packt das
# Ergebnis selbst — nicht das, was GitHub als Tarball ausliefert. Der Hash muss
# also ueber genau diese Schritte entstehen, sonst schlaegt die Pruefung beim
# Build fehl. Nachgebaut aus include/download.mk:
#
#   git clone && git checkout $SOURCE_VERSION
#   git archive --format=tar HEAD              (beachtet .gitattributes)
#   tar --numeric-owner --owner=0 --group=0 --mode=a-s --sort=name
#       --mtime=@<commit-zeit>
#   zstd -T0 --ultra -20
#
# Die feste mtime aus der Commit-Zeit ist der Grund, warum derselbe Commit
# immer denselben Hash ergibt. Wer das nicht glaubt: zweimal laufen lassen.
#
# Geprueft, nicht angenommen: dieselben Schritte auf rtl826x-firmware
# (PKG_SOURCE_DATE 2026-01-24) ergeben exakt den PKG_MIRROR_HASH aus dessen
# Makefile im Upstream-Baum. Aeltere Tarballs auf sources.openwrt.org stammen
# noch aus der xz-Zeit und wurden spaeter umgepackt — die taugen nicht als
# Referenz, ihr Hash ist mit keinem zstd von heute zu treffen.
# --------------------------------------------------------------------------
say "mirror-hash berechnen"
PKG_NAME=apman
FEED_MK="$FEED/apman/Makefile"
[ -f "$FEED_MK" ] || { echo "kein feed-makefile: $FEED_MK" >&2; exit 1; }
OLD_VER="$(sed -n 's/^PKG_VERSION:=\(.*\)$/\1/p' "$FEED_MK")"
NEW_VER=$((OLD_VER + 1))
SUBDIR="$PKG_NAME-$NEW_VER"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
(
	# umask 022 um ALLES, und beim Auspacken KEIN -p. Das ist nicht Kosmetik:
	# `git archive` schreibt die Dateimodi durch die umask (mit 002 werden aus
	# 644 dann 664), und `tar -x` ohne -p legt sie wieder durch die umask an.
	# Beides zusammen entscheidet ueber Byte 106 jedes tar-Headers und damit
	# ueber den Hash. Verifiziert gegen rtl826x-firmware aus dem Upstream-Baum:
	# mit umask 022 exakt der Hash aus dessen Makefile, mit 002 nicht.
	umask 022
	git clone -q "$HTTPS_URL" "$TMP/$SUBDIR"
	git -C "$TMP/$SUBDIR" checkout -q "$COMMIT"
	TAR_TIMESTAMP="$(git -C "$TMP/$SUBDIR" log -1 --no-show-signature --format='@%ct')"
	git -C "$TMP/$SUBDIR" config core.abbrev 8
	git -C "$TMP/$SUBDIR" archive --format=tar HEAD --output="$TMP/$SUBDIR.tar.git"
	rm -rf "$TMP/$SUBDIR"; mkdir "$TMP/$SUBDIR"
	tar -C "$TMP/$SUBDIR" -xf "$TMP/$SUBDIR.tar.git"
	cd "$TMP" && tar --numeric-owner --owner=0 --group=0 --mode=a-s --sort=name \
		--mtime="$TAR_TIMESTAMP" -c "$SUBDIR" | zstd -T0 --ultra -20 -q -o "$TMP/$SUBDIR.tar.zst"
)
HASH="$(sha256sum "$TMP/$SUBDIR.tar.zst" | cut -d' ' -f1)"
echo "tarball: $SUBDIR.tar.zst  ($(stat -c%s "$TMP/$SUBDIR.tar.zst") bytes)"
echo "sha256:  $HASH"

# --------------------------------------------------------------------------
# 3. Feed nachziehen
# --------------------------------------------------------------------------
say "feed bumpen: $FEED_MK"
sed -i \
	-e "s|^PKG_VERSION:=.*|PKG_VERSION:=$NEW_VER|" \
	-e "s|^PKG_RELEASE:=.*|PKG_RELEASE:=1|" \
	-e "s|^PKG_SOURCE_VERSION:=.*|PKG_SOURCE_VERSION:=$COMMIT|" \
	-e "s|^PKG_MIRROR_HASH:=.*|PKG_MIRROR_HASH:=$HASH|" \
	"$FEED_MK"
grep -E '^PKG_(VERSION|RELEASE|SOURCE_VERSION|MIRROR_HASH)' "$FEED_MK" | sed 's/^/  /'

cd "$FEED"
git add apman/Makefile
git commit -q -m "apman: agent $SHORT

$(cd "$ROOT" && git log -1 --format=%s)"
echo "feed committed: $(git log --oneline -1)"
[ "$FEED_PUSH" = 1 ] && { say "feed push"; git push origin HEAD; }

# --------------------------------------------------------------------------
# 4. Dev-Rollout
# --------------------------------------------------------------------------
for ap in "${DEVS[@]:-}"; do [ -n "$ap" ] && rollout "$ap"; done

say "fertig"
echo "  agent:  $SHORT  ($HTTPS_URL)"
echo "  paket:  $PKG_NAME $NEW_VER-1"
[ "$FEED_PUSH" = 1 ] || echo "  feed ist committet, aber nicht gepusht — contrib/release.sh --feed-push oder von hand"
