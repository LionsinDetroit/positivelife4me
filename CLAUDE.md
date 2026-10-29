# CLAUDE.md

## Approval required before committing or pushing

Before running `git commit` or `git push` (or any other action that commits or pushes changes, including GitHub API file writes):

1. Show the user exactly what changed: the full diff (`git diff` / `git diff --staged`), plus the full contents of any new files.
2. Stop and wait for the user to reply with the word **"approve"**.
3. Only commit and push after receiving "approve". Anything other than "approve" (questions, edits, silence) is not approval. If changes are requested, make them, show the updated diff, and wait again.
4. Approval covers only the exact changes that were shown. Any further change needs a new review and a new "approve".
