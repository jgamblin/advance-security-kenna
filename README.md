# advance-security-kenna

GitHub Advance Security Action to push SARIF files into Kenna

## Setting up an Action

Adding the following step in your workflow file will add in Kenna support.

```yaml
jobs:
  analysis:
    # ...
    steps:
    # ...
    # Rest fo the Action that performs the analysis
    # ...
    - name: Upload to Kenna
      uses: GeekMasher/advance-security-kenna@main
      with:
        endpoint: ${{ secrets.KENNA_URL }}
        token: ${{ secrets.KENNA_TOKEN }}
        connector: 1
```

In this case, two secrets can be added (possibly globally) called:

- `KENNA_URL` - Can be sensitive
- `KENNA_TOKEN` - Very sensitive
