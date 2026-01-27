# Git Quick Reference - Copy to Cursor Rules

## Standard Workflow (Copy These Commands)

### Starting New Work
```bash
git checkout main
git pull origin main
git checkout -b feature/your-feature-name
```

### After PR Merged
```bash
git checkout main
git pull origin main
git branch -d feature/your-feature-name
git push origin --delete feature/your-feature-name
```

### Starting Next Feature
```bash
git checkout main
git pull origin main
git checkout -b feature/next-feature-name
```

## Key Rules
1. Always `git pull origin main` before creating new branch
2. Always work on feature branches, never directly on main
3. Clean up merged branches (delete local + remote)
4. If conflicts occur, resolve on feature branch, not main
