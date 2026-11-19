# nvdmatch · CVEs that really affect an installed version

Asking NVD about a product returns every CVE ever published for it, also the ones fixed years before the installed version. nvdmatch keeps only the CVEs whose CPE match has an explicit version bound that includes the installed version:

- `versionEndExcluding` or `versionEndIncluding`, with the start bounds when present
- the exact version written in the CPE
- open-ended ranges (`versionStartIncluding` alone): affected, no fix yet

A match with no bound at all is skipped, because it cannot say whether this version is affected. Each result has the CVSS score of the newest CVSS version available, a severity and the version that fixes it.

```bash
python3 nvdmatch.py lookup mozilla firefox 115.0
python3 nvdmatch.py check inventory.json --budget 120     # [{"vendor", "product", "version", "name"}]
python3 nvdmatch.py match saved-answer.json mozilla firefox 115.0     # offline
```

```python
import nvdmatch
client = nvdmatch.NVDClient("nvd-cache.json")
for c in client.lookup("videolan", "vlc_media_player", "3.0.11"):
    print(c["id"], c["severity"], c["fixed_in"])
```

Notes:
- Only vendor, product and version are sent to NVD. Answers are cached for 7 days.
- Without an API key NVD allows 5 requests in 30 seconds: the client waits 6.5 s between requests. Set `NVD_API_KEY` to go faster.
- By default only the newest 500 answers are read: for an installed version the recent CVEs are the ones that matter, and NVD lists them last. `--all-pages` reads everything.
- Versions are compared number by number (`2.10` is newer than `2.9`). Letters count as 0, so `2.4.1-beta` equals `2.4.1`.

This product uses the NVD API but is not endorsed or certified by the NVD.

Licence: Apache-2.0
