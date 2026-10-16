#!/usr/bin/env bash

cd /d/SecureSense || exit 1

pause_at_end() {
    echo
    echo "========================================"
    echo "Push script finished."
    echo "Review the result above before closing."
    echo "========================================"
    read -r -p "Press Enter to close this script..."
}

trap pause_at_end EXIT

echo "========================================"
echo "       SECURESENSE GIT PUSH"
echo "========================================"

echo
echo "[1/4] Current repository status"
git status --short --branch || exit 1

echo
echo "[2/4] Review changes"
git diff --stat
git diff --check || exit 1

echo
echo "[3/4] Prepare commit"
echo "This will stage all repository changes."
read -r -p "Continue with staging, commit and push? (y/N): " confirm

if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
    echo "Cancelled. No files were staged or committed by this script."
    exit 0
fi

git add -A || exit 1

echo
git status --short

read -r -p "Enter commit message: " commit_message
if [[ -z "$commit_message" ]]; then
    echo "Empty commit message. Stopping."
    exit 1
fi

git commit -m "$commit_message" || exit 1

echo
echo "[4/4] Push to GitHub"
git push origin master
push_result=$?

if [[ $push_result -eq 0 ]]; then
    echo
    echo "SUCCESS: Git push completed."
    git log -1 --oneline
else
    echo
    echo "FAILED: Git push returned exit code $push_result."
    echo "Your local commit is retained; inspect the error above."
fi

exit "$push_result"
