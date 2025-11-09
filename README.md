# Local Tab Suspender

This repository now focuses on the privacy-first Manifest V3 rewrite of The
Great Suspender. The new extension lives in [`local-suspender/`](local-suspender/)
and operates entirely offline with no network access. The original Manifest V2
codebase is kept only for historical reference under
[`legacy/original-mv2/`](legacy/original-mv2/).

## Install the local extension for development

1. Clone this repository.
2. Open Chrome and navigate to `chrome://extensions/`.
3. Enable **Developer mode** in the upper-right corner.
4. Click **Load unpacked** and select the `local-suspender/` directory.

## Package a local-only build

The repo provides an offline packaging script that creates a versioned archive
containing only the Manifest V3 extension.

```bash
npm run package:local-suspender
```

The script zips `local-suspender/` into `dist/local-suspender-<version>.zip`
using the version number defined in `local-suspender/manifest.json`. You can
extract that archive and load it with **Load unpacked** for testing. Because the
process is entirely local there are no network requests.

## Legacy sources

The previous Manifest V2 implementation remains available in
[`legacy/original-mv2/`](legacy/original-mv2/) for code archeology, but it is no
longer built or supported. Any historical tooling such as the Grunt pipeline is
considered archived—refer to [`legacy/README.md`](legacy/README.md) for details.
