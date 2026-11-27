"""
verilay_countries.py: "Apps checked from all over the world" on the homepage (Moses, 27 Nov 2026).

Counts the countries real scans came from, over all time: Verilay's own accuracy-check scans and the owner's own apps
(the same list as the "different apps checked" number, verilay_appcount.exclude_patterns) are left out. Only country
names are ever shown: never apps, times or how many scans a country made, so nobody can be picked out. The answer is kept
for an hour. If anything fails, the line is simply not shown.
"""
import html
import threading
import time

CACHE_SECONDS = 3600
SHOW_FIRST = 6           # names shown before "and N more"
MIN_COUNTRIES = 3        # fewer than this: not worth a line

NAMES = {
    "AD": "Andorra", "AE": "the United Arab Emirates", "AF": "Afghanistan", "AG": "Antigua and Barbuda", "AL": "Albania",
    "AM": "Armenia", "AO": "Angola", "AR": "Argentina", "AT": "Austria", "AU": "Australia", "AZ": "Azerbaijan",
    "BA": "Bosnia and Herzegovina", "BB": "Barbados", "BD": "Bangladesh", "BE": "Belgium", "BF": "Burkina Faso",
    "BG": "Bulgaria", "BH": "Bahrain", "BI": "Burundi", "BJ": "Benin", "BN": "Brunei", "BO": "Bolivia", "BR": "Brazil",
    "BS": "the Bahamas", "BT": "Bhutan", "BW": "Botswana", "BY": "Belarus", "BZ": "Belize", "CA": "Canada",
    "CD": "the DR Congo", "CF": "the Central African Republic", "CG": "the Republic of the Congo", "CH": "Switzerland",
    "CI": "Côte d'Ivoire", "CL": "Chile", "CM": "Cameroon", "CN": "China", "CO": "Colombia", "CR": "Costa Rica", "CU": "Cuba",
    "CV": "Cape Verde", "CY": "Cyprus", "CZ": "Czechia", "DE": "Germany", "DJ": "Djibouti", "DK": "Denmark",
    "DM": "Dominica", "DO": "the Dominican Republic", "DZ": "Algeria", "EC": "Ecuador", "EE": "Estonia", "EG": "Egypt",
    "ER": "Eritrea", "ES": "Spain", "ET": "Ethiopia", "FI": "Finland", "FJ": "Fiji", "FR": "France", "GA": "Gabon",
    "GB": "the United Kingdom", "GD": "Grenada", "GE": "Georgia", "GH": "Ghana", "GM": "the Gambia", "GN": "Guinea",
    "GQ": "Equatorial Guinea", "GR": "Greece", "GT": "Guatemala", "GW": "Guinea-Bissau", "GY": "Guyana", "HK": "Hong Kong",
    "HN": "Honduras", "HR": "Croatia", "HT": "Haiti", "HU": "Hungary", "ID": "Indonesia", "IE": "Ireland", "IL": "Israel",
    "IN": "India", "IQ": "Iraq", "IR": "Iran", "IS": "Iceland", "IT": "Italy", "JM": "Jamaica", "JO": "Jordan", "JP": "Japan",
    "KE": "Kenya", "KG": "Kyrgyzstan", "KH": "Cambodia", "KM": "Comoros", "KN": "Saint Kitts and Nevis", "KR": "South Korea",
    "KW": "Kuwait", "KZ": "Kazakhstan", "LA": "Laos", "LB": "Lebanon", "LC": "Saint Lucia", "LI": "Liechtenstein",
    "LK": "Sri Lanka", "LR": "Liberia", "LS": "Lesotho", "LT": "Lithuania", "LU": "Luxembourg", "LV": "Latvia", "LY": "Libya",
    "MA": "Morocco", "MC": "Monaco", "MD": "Moldova", "ME": "Montenegro", "MG": "Madagascar", "MK": "North Macedonia",
    "ML": "Mali", "MM": "Myanmar", "MN": "Mongolia", "MO": "Macau", "MR": "Mauritania", "MT": "Malta", "MU": "Mauritius",
    "MV": "the Maldives", "MW": "Malawi", "MX": "Mexico", "MY": "Malaysia", "MZ": "Mozambique", "NA": "Namibia",
    "NE": "Niger", "NG": "Nigeria", "NI": "Nicaragua", "NL": "the Netherlands", "NO": "Norway", "NP": "Nepal",
    "NZ": "New Zealand", "OM": "Oman", "PA": "Panama", "PE": "Peru", "PG": "Papua New Guinea", "PH": "the Philippines",
    "PK": "Pakistan", "PL": "Poland", "PR": "Puerto Rico", "PS": "Palestine", "PT": "Portugal", "PY": "Paraguay",
    "QA": "Qatar", "RO": "Romania", "RS": "Serbia", "RU": "Russia", "RW": "Rwanda", "SA": "Saudi Arabia",
    "SB": "the Solomon Islands", "SC": "Seychelles", "SD": "Sudan", "SE": "Sweden", "SG": "Singapore", "SI": "Slovenia",
    "SK": "Slovakia", "SL": "Sierra Leone", "SN": "Senegal", "SO": "Somalia", "SR": "Suriname", "SS": "South Sudan",
    "SV": "El Salvador", "SY": "Syria", "SZ": "Eswatini", "TD": "Chad", "TG": "Togo", "TH": "Thailand", "TJ": "Tajikistan",
    "TL": "Timor-Leste", "TM": "Turkmenistan", "TN": "Tunisia", "TO": "Tonga", "TR": "Türkiye", "TT": "Trinidad and Tobago",
    "TW": "Taiwan", "TZ": "Tanzania", "UA": "Ukraine", "UG": "Uganda", "US": "the United States", "UY": "Uruguay",
    "UZ": "Uzbekistan", "VE": "Venezuela", "VN": "Vietnam", "WS": "Samoa", "XK": "Kosovo", "YE": "Yemen",
    "ZA": "South Africa", "ZM": "Zambia", "ZW": "Zimbabwe",
}

_lock = threading.Lock()
_cache = {"value": None, "at": 0.0}


def _excluded(repo, patterns):
    r = str(repo or "").strip().lower()
    for p in patterns:
        if p.endswith("%") and r.startswith(p[:-1]):
            return True
        if r == p:
            return True
    return False


def count_countries(rows, patterns):
    """{country code: real scans} from report rows ({country, repo, eval}). Test and own scans are left out."""
    out = {}
    for r in rows or []:
        cc = str((r or {}).get("country") or "").upper()
        if len(cc) != 2 or cc not in NAMES:
            continue
        if str(r.get("eval")).lower() == "true" or _excluded(r.get("repo"), patterns):
            continue
        out[cc] = out.get(cc, 0) + 1
    return out


def ordered_names(counts):
    """Country names, most scans first (ties by name)."""
    return [NAMES[c] for c, _n in sorted(counts.items(), key=lambda kv: (-kv[1], NAMES[kv[0]].removeprefix("the ")))]


def scale_text(n):
    """'20+ countries' rounded DOWN to the ten (Moses, 27 Nov 2026: no exact number that changes every week); under 10:
    'around the world'."""
    return f"{n // 10 * 10}+ countries" if n >= 10 else "around the world"


def line_html(names):
    """The homepage line, or '' when there are too few countries."""
    if len(names) < MIN_COUNTRIES:
        return ""
    esc = html.escape
    first, rest = names[:SHOW_FIRST], names[SHOW_FIRST:]
    head = ('<div class="hx-countries" style="margin-top:14px;background:#fff;border:.5px solid var(--bdr,#e4e2f5);border-radius:12px;'
            'padding:.7rem 1rem;font-size:14px;line-height:1.6;color:var(--txt)">&#127757; <strong style="color:var(--put,#3C3489)">'
            f'Builders from {esc(scale_text(len(names)))} have checked their apps with Verilay</strong>, including ')
    foot = ('<div style="font-size:12px;color:var(--mut,#6b6966);margin-top:2px">Countries only, never apps or times. Our own and '
            'test scans are left out.</div></div>')
    if not rest:
        return head + esc(", ".join(first[:-1]) + " and " + first[-1]) + "." + foot
    rest_txt = ", " + ", ".join(rest[:-1]) + (" and " if len(rest) > 1 else "") + rest[-1] + "."
    if len(rest) == 1:
        rest_txt = " and " + rest[0] + "."
    return (head + esc(", ".join(first))
            + '<details style="display:inline"><summary style="display:inline;cursor:pointer;color:var(--pu,#534AB7);font-weight:600;'
            'list-style:none">&nbsp;and more &#9662;</summary><span>' + esc(rest_txt) + '</span></details>' + foot)


def countries_line(sb, patterns, now=None):
    """The homepage line, from the reports table, cached for an hour. '' on any problem."""
    if sb is None:
        return ""
    now = now if now is not None else time.time()
    with _lock:
        if _cache["value"] is not None and now - _cache["at"] < CACHE_SECONDS:
            return _cache["value"]
    try:
        rows, start, step = [], 0, 1000
        while start < 20000:
            batch = (sb.table("reports").select("country:data->>country,repo,eval:data->>eval")
                     .range(start, start + step - 1).execute().data or [])
            rows += batch
            if len(batch) < step:
                break
            start += step
        val = line_html(ordered_names(count_countries(rows, patterns)))
    except Exception as e:
        print(f"[home] countries line unavailable: {type(e).__name__}", flush=True)
        with _lock:
            _cache.update(value="", at=now - CACHE_SECONDS + 300)     # try again in 5 minutes
        return ""
    with _lock:
        _cache.update(value=val, at=now)
    return val
