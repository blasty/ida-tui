#!/bin/sh
# Install & enable the idatui-mcp user service. Re-run after editing the unit.
set -eu

UNIT=idatui-mcp.service
SRC=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/$UNIT
DEST_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"

mkdir -p "$DEST_DIR"
ln -sf "$SRC" "$DEST_DIR/$UNIT"

# Keep the service alive after logout / across reboots without a login session.
loginctl enable-linger "$(id -un)" || true

systemctl --user daemon-reload
systemctl --user enable --now "$UNIT"

echo
echo "Installed. Handy commands:"
echo "  systemctl --user status  idatui-mcp"
echo "  systemctl --user restart idatui-mcp"
echo "  journalctl --user -u idatui-mcp -f"
echo "  systemctl --user edit    idatui-mcp   # drop-in overrides (ports, workers)"
