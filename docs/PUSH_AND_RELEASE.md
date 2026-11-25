# Pushing and releasing v1.0.0

The commit history for v1.0.0 is built and tagged locally. The preparation
environment has **no GitHub credentials**, so the push itself has to be made
by you (or by this agent once a credential is configured). Nothing has been
pushed, nothing has been force-pushed, and no remote content has been
modified.

## Verified remote state before any push

Checked against the GitHub API on 25 November 2026:

| Property | Value |
|---|---|
| Repository | https://github.com/Alana11539/CAGE |
| Visibility | public |
| Default branch | `main` |
| Branches / commits / tags / releases | 0 / 0 (empty repository) / 0 / 0 |

Because the repository is empty there is nothing to overwrite: the first push
is a fast-forward creation of `main`, not a replacement. **No force push is
needed and none should be used.**

Note that the repository is **public**: everything pushed is world-readable.
`python scripts/secret_scan.py` reported no credential-shaped filenames or
content across 141 files, and `.gitignore` excludes `.env*`, `*.key`,
`*.pem`, `secrets/`, `config/local_*.yaml`, `runs/`, `results/` and coverage
output.

## Option A — you push from your own machine (recommended)

1. Download `cage_v1.0.0_phase1.bundle` from this session.
2. Clone from the bundle and attach your remote:

   ```bash
   git clone cage_v1.0.0_phase1.bundle CAGE
   cd CAGE
   git remote remove origin
   git remote add origin https://github.com/Alana11539/CAGE.git
   git push -u origin main
   git push origin v1.0.0
   ```

3. The bundle carries all 13 commits and the annotated `v1.0.0` tag, so the
   history arrives intact.

### Commit author identity

The commits were authored as
`Alana11539 <Alana11539@users.noreply.github.com>` — GitHub's no-reply form
for your account, chosen so that no personal e-mail address is written into
the repository. If you would rather they carry your own address, rewrite
before pushing:

```bash
git -c user.name="Your Name" -c user.email="you@example.org" \
    rebase --root --exec 'git commit --amend --no-edit --reset-author'
git tag -f -a v1.0.0 -m "CAGE v1.0.0"
```

## Option B — the agent pushes for you

Add a GitHub credential to this workspace: **Customize → Credentials →
Connect** next to GitHub, then say so in chat. Do **not** paste a token or a
password into the conversation. Once the credential is stored, the push can be
made from here with the same commands.

## Creating the release — after your approval

1. **Switch on the Zenodo integration first.** Zenodo only archives releases
   created *after* the repository toggle is enabled; see
   `docs/ZENODO_ARCHIVAL.md`.
2. Create the release from the existing tag `v1.0.0` (GitHub → Releases →
   Draft a new release → choose the existing tag), with
   `docs/RELEASE_NOTES_v1.0.0.md` as the body.
3. Leave it as a **draft** until the contents have been reviewed. Publishing
   is the archival trigger and is the step that needs your explicit approval.
4. After publication, record the Zenodo **Version DOI** (not the concept DOI)
   in `CITATION.cff`, in the README badge, and in the manuscript's data and
   code availability statements, then commit that change.
