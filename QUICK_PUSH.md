# Quick Push Reference

## 🚀 Fastest Way to Push

### Using PowerShell (Windows)
```powershell
cd "c:\Users\ayush\OneDrive\Music\open source\localstack"
.\push-changes.ps1
```

### Using Bash (Linux/Mac/WSL)
```bash
cd "/c/Users/ayush/OneDrive/Music/open source/localstack"
chmod +x push-changes.sh
./push-changes.sh
```

### Manual Commands (If scripts don't work)

**Single Commit:**
```bash
cd "c:\Users\ayush\OneDrive\Music\open source\localstack"

git add localstack-core/localstack/services/stepfunctions/provider.py
git add localstack-core/localstack/services/firehose/provider.py
git add localstack-core/localstack/services/lambda_/provider.py
git add localstack-core/localstack/services/stepfunctions/backend/test_state/execution.py
git add localstack-core/localstack/services/stepfunctions/backend/test_state/execution_worker.py
git add localstack-core/localstack/services/stepfunctions/asl/eval/test_state/environment.py
git add BUG_FIXES_SUMMARY.md

git commit -m "fix: resolve 4 critical bugs across Lambda, StepFunctions, and Firehose"

git push origin main
# Or: git push origin <your-branch-name>
```

## 📋 Pre-Push Checklist

- [ ] All 7 files are modified and saved
- [ ] You're on the correct branch
- [ ] You have commit access to your fork
- [ ] You've reviewed the changes with `git diff`

## 🔍 Verify Changes

```bash
# See what files changed
git status

# Review changes
git diff

# See commit history
git log --oneline -5
```

## 🌿 Branch Options

**Option A: Push to existing branch**
```bash
git push origin main
```

**Option B: Create new branch**
```bash
git checkout -b fix/multiple-service-bugs
git push -u origin fix/multiple-service-bugs
```

**Option C: Push to your fork**
```bash
git remote add myfork https://github.com/YOUR_USERNAME/localstack.git
git push myfork main
```

## 🔧 Troubleshooting

**Error: "Permission denied"**
- Make sure you're pushing to your fork, not the main repo
- Check your GitHub authentication

**Error: "Updates were rejected"**
- Pull latest changes first: `git pull origin main`
- Or force push (careful!): `git push -f origin <branch>`

**Error: "No such file or directory"**
- Make sure you're in the localstack directory
- Check file paths are correct

## 📝 After Pushing

1. Go to https://github.com/localstack/localstack
2. Click "Pull requests" → "New pull request"
3. Select your fork and branch
4. Use this PR title:
   ```
   fix: resolve 4 critical bugs across Lambda, StepFunctions, and Firehose
   ```
5. In PR description, paste content from `BUG_FIXES_SUMMARY.md`
6. Reference issues: #13351, #13315, #13301, #13215

## 📞 Need Help?

- Review `COMMIT_GUIDE.md` for detailed instructions
- Check `BUG_FIXES_SUMMARY.md` for what was fixed
- Run scripts with `-h` or `--help` for options (if implemented)
