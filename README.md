# rickuf.github.io

Tobias Wicke's personal blog — Jekyll 4, deployed to GitHub Pages via Actions.

## Local development

No Ruby on the host: everything runs in the dev container.

1. Open the repo in VS Code and run **Dev Containers: Reopen in Container**.
2. `bin/serve`
3. Browse to <http://localhost:4000>.

`bin/serve` runs with `--drafts`, `--livereload` and `--incremental`, so posts in
`_drafts/` are visible locally and the browser refreshes on save.

## Deployment

`.github/workflows/pages.yml` builds the site on every push to `main` and deploys it
with `actions/deploy-pages`. This requires **Settings → Pages → Source: GitHub Actions**
in the repo — the older "deploy from a branch" mode runs GitHub's own Jekyll 3
pipeline and would ignore both this workflow and the Jekyll 4 Gemfile.
