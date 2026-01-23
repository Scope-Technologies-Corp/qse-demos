# Git Workflow Guide - Best Practices

## Standard Workflow for Feature Development

### 1. Starting New Work (Create Feature Branch)

```bash
# Always start from an up-to-date main branch
git checkout main
git pull origin main

# Create and switch to new feature branch
git checkout -b feature/your-feature-name

# Verify you're on the new branch
git branch
```

**Example:**
```bash
git checkout main
git pull origin main
git checkout -b feature/add-new-test
```

---

### 2. Working on Your Feature

```bash
# Make your changes, then stage and commit
git add .
git commit -m "Descriptive commit message"

# Or commit specific files
git add file1.py file2.py
git commit -m "Update specific files"
```

**Best Practice:** Commit often with clear, descriptive messages.

---

### 3. Pushing Your Feature Branch

```bash
# Push your branch to remote (first time)
git push -u origin feature/your-feature-name

# For subsequent pushes (after commits)
git push
```

**Note:** The `-u` flag sets up tracking so future `git push` works without specifying remote/branch.

---

### 4. After PR is Merged to Main

Once your Pull Request is merged on GitHub/GitLab:

```bash
# Step 1: Switch back to main
git checkout main

# Step 2: Pull the latest changes (including your merged PR)
git pull origin main

# Step 3: Delete your local feature branch (optional cleanup)
git branch -d feature/your-feature-name

# Step 4: Delete the remote branch (if it still exists)
git push origin --delete feature/your-feature-name

# Step 5: Verify you're up to date
git log --oneline -5
git status
```

**Complete cleanup example:**
```bash
git checkout main
git pull origin main
git branch -d feature/add-new-test
git push origin --delete feature/add-new-test
git log --oneline -5
```

---

### 5. Starting Fresh Work (After Previous PR Merged)

```bash
# Step 1: Ensure main is up to date
git checkout main
git pull origin main

# Step 2: Verify clean state
git status  # Should show "nothing to commit, working tree clean"

# Step 3: Create new feature branch
git checkout -b feature/next-feature-name

# Step 4: Start working
# ... make your changes ...
```

---

## Avoiding Merge Conflicts

### Before Starting Work

**Always pull latest main first:**
```bash
git checkout main
git pull origin main
```

### If You Get Behind (Main Has New Commits)

**Option 1: Rebase your feature branch (recommended for cleaner history)**
```bash
# On your feature branch
git checkout feature/your-feature-name
git rebase main

# If conflicts occur, resolve them, then:
git add .
git rebase --continue

# Force push (only if you've already pushed before)
git push --force-with-lease
```

**Option 2: Merge main into your feature branch**
```bash
# On your feature branch
git checkout feature/your-feature-name
git merge main

# Resolve conflicts if any, then:
git add .
git commit -m "Merge main into feature branch"
git push
```

---

## Quick Reference Commands

### Check Current Status
```bash
git status                    # See what's changed
git branch                    # List local branches
git branch -a                 # List all branches (local + remote)
git log --oneline -10         # See recent commits
```

### Compare Branches
```bash
git diff main..feature/your-branch    # See differences
git log main..feature/your-branch      # Commits in feature not in main
git log feature/your-branch..main     # Commits in main not in feature
```

### Undo Changes (if needed)
```bash
git restore <file>            # Discard changes to a file
git restore --staged <file>   # Unstage a file
git reset HEAD~1               # Undo last commit (keep changes)
git reset --hard HEAD~1        # Undo last commit (discard changes)
```

---

## Complete Workflow Example

```bash
# ============================================
# STARTING NEW FEATURE
# ============================================

# 1. Update main
git checkout main
git pull origin main

# 2. Create feature branch
git checkout -b feature/user-authentication

# 3. Work and commit
git add .
git commit -m "Add user login functionality"
git push -u origin feature/user-authentication

# 4. Create PR on GitHub/GitLab, get it reviewed and merged

# ============================================
# AFTER PR IS MERGED
# ============================================

# 5. Clean up
git checkout main
git pull origin main
git branch -d feature/user-authentication
git push origin --delete feature/user-authentication

# 6. Ready for next feature
git checkout -b feature/add-dashboard
```

---

## Troubleshooting

### "Your branch and 'origin/main' have diverged"

This means your local main has commits that remote doesn't, and vice versa.

**Solution:**
```bash
# If you don't need your local commits on main
git checkout main
git reset --hard origin/main

# If you need to keep local changes, merge instead
git checkout main
git pull origin main --no-rebase
```

### "Merge conflict" during pull

```bash
# See what files have conflicts
git status

# Resolve conflicts in files, then:
git add <resolved-files>
git commit -m "Resolve merge conflicts"
```

### Accidentally committed to main

```bash
# Create branch from current state
git branch feature/fix-accidental-commit

# Reset main to match remote
git checkout main
git reset --hard origin/main

# Continue work on feature branch
git checkout feature/fix-accidental-commit
```

---

## Best Practices Summary

1. ✅ **Always start from updated main**: `git checkout main && git pull origin main`
2. ✅ **Use descriptive branch names**: `feature/`, `fix/`, `docs/`
3. ✅ **Commit often** with clear messages
4. ✅ **Pull before pushing** if working with others
5. ✅ **Clean up merged branches** to keep repo tidy
6. ✅ **Never force push to main** (protect main branch)
7. ✅ **Use `--force-with-lease`** instead of `--force` if needed

---

## Recommended Git Configuration

```bash
# Set default branch name
git config --global init.defaultBranch main

# Set pull strategy (merge is safer than rebase for beginners)
git config --global pull.rebase false

# Or use rebase for cleaner history (advanced)
git config --global pull.rebase true

# Set your name and email
git config --global user.name "Your Name"
git config --global user.email "your.email@example.com"
```
