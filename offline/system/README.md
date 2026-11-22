# Локальный apt-репозиторий

Содержит `.deb` для offline-установки на Debian 13 / Kali Linux amd64:

- Podman и rootless-зависимости (`conmon`, `crun`, `netavark`, `uidmap`,
  `slirp4netns`, `passt`, `fuse-overlayfs`);
- Python 3.13 / `python3.13-venv`;
- `curl`, `zstd`, `ca-certificates`;
- Apache 2.4/OpenSSL — для `--with-apache`.

Индекс репозитория — `Packages`/`Packages.gz`, метаданные — `Release`.
Сам каталог `debs/` и индекс исключены из git из-за размера, но входят в
`offline/dist/honeypot-orchestrator_1.0.0_amd64.deb`.

Подключение:

```bash
echo "deb [trusted=yes] file:$(pwd)/offline/system ./" | sudo tee /tmp/hp-offline.list
sudo apt-get -o Dir::Etc::sourcelist=/tmp/hp-offline.list \
  -o Dir::Etc::sourceparts=- update
```

Полная инструкция: [`../docs/OFFLINE_INSTALL.md`](../docs/OFFLINE_INSTALL.md).
