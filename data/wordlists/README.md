# PT Journal - Bundled Wordlists

This directory contains common wordlists for security testing with Gobuster and other tools.

## Included Wordlists

### common.txt (38 KB)

- **Source**: SecLists - Discovery/Web-Content/common.txt
- **Use case**: Directory and file brute-forcing
- **Entries**: ~4,600 common web paths
- **Example**: `gobuster dir -u http://example.com -w data/wordlists/common.txt`

### subdomains.txt (33 KB)

- **Source**: SecLists - Discovery/DNS/subdomains-top1million-5000.txt
- **Use case**: DNS subdomain enumeration
- **Entries**: Top 5,000 most common subdomains
- **Example**: `gobuster dns -d example.com -w data/wordlists/subdomains.txt`

### vhosts.txt (1.6 MB)

- **Source**: SecLists - Discovery/DNS/namelist.txt
- **Use case**: Virtual host discovery
- **Entries**: ~150,000 names
- **Example**: `gobuster vhost -u http://example.com -w data/wordlists/vhosts.txt`

## Getting More Wordlists

For comprehensive security testing, download the full SecLists repository:

```bash
# Clone SecLists (includes all wordlists)
git clone https://github.com/danielmiessler/SecLists.git

# Or download specific lists
curl -L -o big.txt https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/big.txt
curl -L -o directory-list-2.3-medium.txt https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-medium.txt
```

## Credits

All wordlists are from the [SecLists](https://github.com/danielmiessler/SecLists) project by Daniel Miessler.

## License

SecLists wordlists are licensed under the MIT License. See the [SecLists repository](https://github.com/danielmiessler/SecLists) for details.
