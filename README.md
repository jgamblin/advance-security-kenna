# advance-security-kenna

GitHub Advance Security Action to push SARIF results into Kenna

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
      # [optional] Only push Vulnerabilities if in production
      # if: ${{ github.ref == 'refs/heads/master' }}
      # Action Properties/Settings
      with:
        endpoint: ${{ secrets.KENNA_URL }}
        kenna_token: ${{ secrets.KENNA_TOKEN }}
        connector: 1
```

In this case, two secrets can be added (possibly globally) called:

- `KENNA_URL` - Can be sensitive
- `KENNA_TOKEN` - Very sensitive


## Running Locally

### Command Line

```bash
python -m ghas_kenna \
  -e "https://api.kennasecurity.com" \
  -k "$KENNA_TOKEN" \
  -c 1234 \
  -i "./results"
```

### Docker

```bash
# Build 
docker build -t ghas_kenna .
# Run container
docker run ghas_kenna --help
```
