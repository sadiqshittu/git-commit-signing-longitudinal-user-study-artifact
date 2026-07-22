# %%
# %% [2] IMPORTS
from pathlib import Path
import pandas as pd
import numpy as np
from scipy.stats import gmean
import tempfile
import shutil
import subprocess
import re
import tarfile
import zipfile
from IPython.display import display
import warnings
warnings.filterwarnings("ignore")

# ===========================================================
# PART 1 — FIRST DEVICE SETUP
# ===========================================================

from scipy import stats
import numpy as np

def mean_ci(data, confidence=0.95):
    """Return (mean, lower, upper) for a 95% CI using t-distribution."""
    n = data.dropna().shape[0]
    m = data.mean()
    se = stats.sem(data.dropna())
    h = se * stats.t.ppf((1 + confidence) / 2, df=n - 1)
    return round(m, 1), round(m - h, 1), round(m + h, 1)

# %%
df = pd.read_csv(Path("..") / "Data" / "Assignment 1" / "ASQ_SUS_Time_first_setup.csv")

# ---------- ASQ ----------
asq_items = ["Ease_of_Setting_Up", "Time", "Support_Information"]
df["ASQ_Mean"] = df[asq_items].mean(axis=1)

print("--- ASQ Results ---")
print("Item Means:\n", df[asq_items].mean().round(1))

m, lo, hi = mean_ci(df["ASQ_Mean"])
print(f"Overall ASQ Mean: {m} (95% CI [{lo}, {hi}])")

for item in asq_items:
    m, lo, hi = mean_ci(df[item])
    print(f"  {item}: {m} (95% CI [{lo}, {hi}])")

# ---------- SUS ----------
sus_odd  = ["SUS_1", "SUS_3", "SUS_5", "SUS_7", "SUS_9"]
sus_even = ["SUS_2", "SUS_4", "SUS_6", "SUS_8", "SUS_10"]

df["SUS_Score"] = (
    df[sus_odd].rsub(5).sum(axis=1) +
    df[sus_even].sub(1).sum(axis=1)
) * 2.5

df.loc[df[sus_odd + sus_even].isnull().all(axis=1), "SUS_Score"] = None

print("\n--- SUS Results ---")
m, lo, hi = mean_ci(df["SUS_Score"])
print(f"Overall SUS Score: {m} (95% CI [{lo}, {hi}])")
print(f"N (valid responses): {df['SUS_Score'].dropna().shape[0]}")

# %%
df[["Time_Minutes", "SUS_Score"]].corr()

# %%
df[["Time_Minutes", "ASQ_Mean"]].corr()

# %%
# ---------- Reported Time Analysis ----------
t = pd.to_numeric(df["Time_Minutes"], errors="coerce").dropna()
print("\n--- Time (minutes) ---")
print(t.describe().round(1))
print("Geometric mean (minutes):", round(gmean(t), 1))


# %%
# %% [4] HELPER FUNCTIONS
logs_dir     = Path("..") / "Data" / "Assignment 1" / "GITLOG_1"
pub_keys_dir = Path("..") / "Data" / "Assignment 1" / "PUBLICKEY_1"

def extract_archive(archive_path: Path, dest: Path):
    if archive_path.suffix == ".zip":
        with zipfile.ZipFile(archive_path, "r") as z:
            z.extractall(dest)
    elif archive_path.suffixes[-2:] == [".tar", ".gz"] or archive_path.suffix == ".tgz":
        with tarfile.open(archive_path, "r:*") as t:
            t.extractall(dest)
    else:
        raise ValueError(f"Unsupported archive: {archive_path.name}")

def find_git_repo_root(root: Path):
    for p in [root] + list(root.rglob("*")):
        if p.is_dir() and (p / ".git").exists():
            return p
    return None

def run_git(repo: Path, args):
    return subprocess.run(
        ["git"] + args, cwd=repo, capture_output=True, text=True, check=False
    ).stdout

def parse_git_log(log_raw: str) -> dict:
    """Parse raw git log output into signing metrics. Reused across Part 1, Longitudinal, and Part 2 loops."""
    authors, keys_found, all_statuses, commit_dates = set(), set(), [], []
    signed_count, good_sig_count, used_web_flow = 0, 0, "No"

    for line in log_raw.splitlines():
        parts = line.split("|")
        if len(parts) >= 6:
            h, an, ae, gq, gk, ad = parts
            authors.add(f"{an} <{ae}>")
            commit_dates.append(ad)
            all_statuses.append(gq)
            if gq != "N":
                signed_count += 1
                if gq in ["G", "U"]: good_sig_count += 1
                if gk:
                    keys_found.add(gk.upper())
                    if "@users.noreply.github.com" in ae:
                        used_web_flow = f"Yes ({gk.upper()})"

    return {
        "authors":        authors,
        "keys_found":     keys_found,
        "all_statuses":   all_statuses,
        "commit_dates":   commit_dates,
        "signed_count":   signed_count,
        "good_sig_count": good_sig_count,
        "used_web_flow":  used_web_flow,
    }

def repair_key_text(text):
    if not text or text in ["KEY_NOT_FOUND", "ERROR_READING_FILE"]:
        return text
    text = text.strip()
    text = re.sub(r'^-{3,5}BEGIN PGP PUBLIC KEY BLOCK-{3,5}', '-----BEGIN PGP PUBLIC KEY BLOCK-----', text)
    text = re.sub(r'^-{3,5}END PGP PUBLIC KEY BLOCK-{3,5}', '-----END PGP PUBLIC KEY BLOCK-----', text)
    if text.startswith("mQ") and "-----BEGIN PGP" not in text:
        text = f"-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n{text}\n-----END PGP PUBLIC KEY BLOCK-----"
    parts = text.split('-----')
    if len(parts) >= 5:
        header = "-----BEGIN PGP PUBLIC KEY BLOCK-----"
        footer = "-----END PGP PUBLIC KEY BLOCK-----"
        body   = "".join(parts[2].split())
        return f"{header}\n\n{body}\n{footer}"
    return text

def extract_fingerprint_from_text(key_text):
    if not key_text or key_text in ["KEY_NOT_FOUND", "ERROR_READING_FILE"]: return None
    key_text = repair_key_text(key_text)
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as tmp:
        tmp.write(key_text)
        tmp_path = tmp.name
    try:
        if "ssh-" in key_text:
            result = subprocess.run(["ssh-keygen", "-l", "-f", tmp_path], capture_output=True, text=True)
            if result.returncode == 0: return result.stdout.split()[1]
        result = subprocess.run(["gpg", "--show-keys", "--with-colons", tmp_path], capture_output=True, text=True)
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                if line.startswith("fpr"): return line.split(":")[9][-16:]
    except Exception: return "PROCESSING_ERROR"
    finally: Path(tmp_path).unlink(missing_ok=True)
    return "UNKNOWN_FORMAT"

def get_submitted_key_content(participant_id):
    matches = list(pub_keys_dir.glob(f"{participant_id}*"))
    if matches:
        matches.sort(key=lambda x: len(x.name))
        try: return matches[0].read_text(encoding="utf-8").strip()
        except Exception: return "ERROR_READING_FILE"
    return "KEY_NOT_FOUND"


# %%
# %% [5] MAIN GIT LOG EXECUTION LOOP — PART 1
rows = []

for arch in sorted(logs_dir.iterdir()):
    if not arch.is_file() or arch.suffix not in [".zip", ".tar", ".gz", ".tgz"] and not arch.suffixes[-2:] == [".tar", ".gz"]:
        continue

    participant = arch.stem.split(".")[0]
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        extract_archive(arch, td)
        repo = find_git_repo_root(td)

        if repo is None:
            rows.append({"Participant": participant, "Status": "NO_REPO_FOUND"})
            continue

        log_raw = run_git(repo, ["log", "--pretty=format:%H|%an|%ae|%G?|%GK|%ad", "--date=iso"])
        log_num = run_git(repo, ["rev-list", "--count", "HEAD"]).strip()
        p       = parse_git_log(log_raw)

        first_is_signed = first_is_good = False
        lines = log_raw.splitlines()
        if lines:
            first_parts = lines[-1].split("|")
            if len(first_parts) >= 4:
                first_gq        = first_parts[3]
                first_is_signed = (first_gq != "N")
                first_is_good   = (first_gq in ["G", "U"])

        rows.append({
            "Participant":               participant,
            "Authors_Found_In_GitLog":   "; ".join(sorted(p["authors"])),
            "GitHub_Web_Flow_Used":      p["used_web_flow"],
            "Commit_Count":              int(log_num) if log_num.isdigit() else len(p["commit_dates"]),
            "Signed_Commit_Count":       p["signed_count"],
            "Good_Signature_Count":      p["good_sig_count"],
            "Unsigned_Commit_Count":     len(p["commit_dates"]) - p["signed_count"],
            "Signature_Status_Sequence": " -> ".join(reversed(p["all_statuses"])),
            "Has_Technical_Errors":      "E" in p["all_statuses"],
            "Has_Bad_Signatures":        "B" in p["all_statuses"],
            "Keys_Found_In_GitLog":      ",".join(sorted(p["keys_found"])) if p["keys_found"] else None,
            "Key_Count_In_GitLog":       len(p["keys_found"]),
            "First_Commit_Time":         p["commit_dates"][-1] if p["commit_dates"] else None,
            "Last_Commit_Time":          p["commit_dates"][0]  if p["commit_dates"] else None,
            "FirstCommitIsSigned":       first_is_signed,
            "FirstCommitIsGoodSig":      first_is_good,
        })

git_summary = pd.DataFrame(rows).sort_values("Participant")

# %%
# %% [6] PUBLIC KEY VERIFICATION — PART 1
git_summary["Submitted_Public_Key"]            = git_summary["Participant"].apply(get_submitted_key_content)
git_summary["Extracted_Submitted_Fingerprint"] = git_summary["Submitted_Public_Key"].apply(extract_fingerprint_from_text)

def verify_match(row):
    if not row["Extracted_Submitted_Fingerprint"]: return "MISSING"
    ext   = str(row["Extracted_Submitted_Fingerprint"]).upper()
    all_k = str(row["Keys_Found_In_GitLog"]).upper()
    if ext in all_k or any(k.strip() in ext for k in all_k.split(',') if len(k.strip()) > 0):
        return "MATCH"
    return "MISMATCH"

git_summary["KeyMatch_Submitted_VS_GitLog"] = git_summary.apply(verify_match, axis=1)

cols = ["Participant", "Signature_Status_Sequence", "KeyMatch_Submitted_VS_GitLog",
        "Has_Technical_Errors", "Good_Signature_Count", "Commit_Count",
        "GitHub_Web_Flow_Used", "Keys_Found_In_GitLog"]
git_summary = git_summary[cols + [c for c in git_summary.columns if c not in cols]]


# %%
# %% [7] MERGE SURVEY + GIT DATA — PART 1
final_df = pd.merge(git_summary, df[['Participant', 'Time_Minutes', 'SUS_Score', 'ASQ_Mean']],
                    on="Participant", how="left")

final_df['First_Commit_Time'] = pd.to_datetime(final_df['First_Commit_Time'], utc=True)
final_df['Last_Commit_Time']  = pd.to_datetime(final_df['Last_Commit_Time'],  utc=True)

final_df['Actual_Time_Minutes'] = (
    (final_df['Last_Commit_Time'] - final_df['First_Commit_Time']).dt.total_seconds() / 60
).round(1)

final_df['Perceived_Time_Minutes'] = pd.to_numeric(final_df['Time_Minutes'], errors='coerce')

# %%
# ---------- Actual Git Log Time Analysis ----------
actual_t        = final_df["Actual_Time_Minutes"].dropna()
active_actual_t = actual_t[actual_t > 0]

print(f"\n--- Actual Git Log Time (Excluding {len(actual_t) - len(active_actual_t)} zeros) ---")
if not active_actual_t.empty:
    print(active_actual_t.describe().round(1))
    print("Geometric mean (minutes):", round(gmean(active_actual_t), 1))
else:
    print("No students had an actual time greater than 0 minutes.")

# %%
# %% [8] PUBLIC KEY TYPE DETECTION
def detect_key_type(key_text: str):
    if not key_text or key_text in ["KEY_NOT_FOUND", "ERROR_READING_FILE"]:
        return "MISSING"
    k = key_text.strip()
    if k.startswith("ssh-") or "ssh-rsa" in k or "ssh-ed25519" in k: return "SSH"
    if "BEGIN PGP PUBLIC KEY BLOCK" in k:                              return "GPG"
    if "BEGIN CERTIFICATE" in k:                                       return "S/MIME"
    return "UNKNOWN"

final_df["Submitted_Key_Type"] = final_df["Submitted_Public_Key"].apply(detect_key_type)

print("\n--- Public Key Type Distribution ---")
print(final_df["Submitted_Key_Type"].value_counts(dropna=False)
    .to_frame("Count")
    .assign(Percentage=lambda x: (x["Count"]/x["Count"].sum()*100).round(1)))

# %%
# %% [9] KEY METADATA (Algorithm + Size)
def extract_key_metadata(key_text, key_type):
    if not key_text or key_text in ["KEY_NOT_FOUND", "ERROR_READING_FILE"]:
        return pd.Series({"Key_Algorithm": None, "Key_Size": None, "Hash_Algorithm": None})

    with tempfile.NamedTemporaryFile(mode="w", delete=False) as tmp:
        tmp.write(key_text)
        tmp_path = tmp.name

    try:
        if "SSH" in key_type:
            r = subprocess.run(["ssh-keygen", "-lf", tmp_path], capture_output=True, text=True)
            if r.returncode == 0:
                parts    = r.stdout.strip().split()
                hash_alg = "SHA-512" if "ED25519" in parts[-1].upper() else "UNKNOWN"
                return pd.Series({"Key_Algorithm": parts[-1], "Key_Size": parts[0], "Hash_Algorithm": hash_alg})

        if "GPG" in key_type:
            r               = subprocess.run(["gpg", "--list-packets", tmp_path], capture_output=True, text=True)
            pref_hash_match = re.search(r'pref-hash-algos: ([\d,]+)', r.stdout)
            GPG_HASH_MAP    = {"2": "SHA-1", "8": "SHA-256", "9": "SHA-384", "10": "SHA-512", "11": "SHA-224"}
            best_hash       = None
            if pref_hash_match:
                first_id  = pref_hash_match.group(1).split(',')[0]
                best_hash = GPG_HASH_MAP.get(first_id, "UNKNOWN")
            r2 = subprocess.run(["gpg", "--show-keys", "--with-colons", tmp_path], capture_output=True, text=True)
            for line in r2.stdout.splitlines():
                if line.startswith("pub"):
                    parts = line.split(":")
                    return pd.Series({"Key_Algorithm": parts[3], "Key_Size": parts[2], "Hash_Algorithm": best_hash})

        if key_type == "S/MIME":
            r             = subprocess.run(["openssl", "x509", "-text", "-noout", "-in", tmp_path], capture_output=True, text=True)
            size_match    = re.search(r'Public-Key: \((\d+) bit\)', r.stdout)
            sig_alg_match = re.search(r'Signature Algorithm: (\w+)', r.stdout)
            hash_part     = None
            if sig_alg_match:
                raw_alg = sig_alg_match.group(1).lower()
                if "sha256" in raw_alg:   hash_part = "SHA-256"
                elif "sha512" in raw_alg: hash_part = "SHA-512"
                elif "sha1" in raw_alg:   hash_part = "SHA-1"
            return pd.Series({"Key_Algorithm": "RSA",
                               "Key_Size": size_match.group(1) if size_match else None,
                               "Hash_Algorithm": hash_part})
    except Exception:
        pass
    finally:
        Path(tmp_path).unlink(missing_ok=True)
    return pd.Series({"Key_Algorithm": None, "Key_Size": None, "Hash_Algorithm": None})

final_df[["Key_Algorithm", "Key_Size", "Hash_Algorithm"]] = final_df.apply(
    lambda r: extract_key_metadata(r["Submitted_Public_Key"], r["Submitted_Key_Type"]), axis=1)

GPG_ALG_MAP = {"1": "RSA", "19": "ECDSA", "22": "Ed25519", "18": "ECDH"}
final_df["Key_Algorithm_Name"] = (
    final_df["Key_Algorithm"].astype(str).map(GPG_ALG_MAP)
    .fillna(final_df["Key_Algorithm"]).astype(str)
    .str.replace(r"[()]", "", regex=True).str.upper())

final_df["Key_Size"] = pd.to_numeric(final_df["Key_Size"], errors="coerce")


# %%
# %% [10] NIST SECURITY STRENGTH
def security_strength_bits(row):
    alg  = str(row["Key_Algorithm_Name"]).upper()
    size = row["Key_Size"]
    if pd.isna(size): return None
    if "RSA" in alg:
        if size >= 15360: return 256
        if size >= 7680:  return 192
        if size >= 3072:  return 128
        if size >= 2048:  return 112
        return 80
    if "ED25519" in alg: return 128
    if "ECDSA" in alg:
        if size >= 512: return 256
        if size >= 384: return 192
        if size >= 256: return 128
        if size >= 224: return 112
        if size >= 160: return 80

final_df["Security_Strength_Bits"] = final_df.apply(security_strength_bits, axis=1)

final_df = final_df.drop(columns=['Time_Minutes', 'Hash_Algorithm', 'Key_Algorithm'], errors='ignore')

with pd.option_context('display.max_columns', None): display(final_df)
final_df.to_csv('../Data/Assignment 1/FIRST_GIT_SIGNING_SETUP.csv', index=False)

# Signature Status Key:
# G (Good): Valid signature; trusted key
# U (Untrusted): Valid signature; unknown trust level
# E (Error): Signature found; public key missing
# N (None): No signature present
# B (Bad): Invalid signature; data mismatch
# X (Expired): Valid signature; key reached expiration
# Y (Expired Key): Valid signature; key is now expired
# R (Revoked): Valid signature; key was cancelled


# %%
# %% [11] FOLLOW-UP ANALYSIS — PART 1
print("=" * 60)
print("FOLLOW-UP ANALYSIS SUMMARY")
print("=" * 60)

total  = len(final_df)
single = (final_df["Commit_Count"] == 1).sum()
multi  = (final_df["Commit_Count"]  > 1).sum()

print(f"\n── 1. Commit Count Distribution ──")
print(f"  Single commit : {single:>3}  ({single/total*100:.1f}%)")
print(f"  Multi commits : {multi:>3}  ({multi/total*100:.1f}%)")

signed_first      = final_df["FirstCommitIsSigned"].sum()
good_signed_first = final_df["FirstCommitIsGoodSig"].sum()

print(f"\n── 2. First Commit Signing ──")
print(f"  First commit signed (any)  : {signed_first:>3}  ({signed_first/total*100:.1f}%)")
print(f"  First commit good sig only : {good_signed_first:>3}  ({good_signed_first/total*100:.1f}%)")

good_first_df = final_df[final_df["FirstCommitIsGoodSig"] == True]
bad_first_df  = final_df[final_df["FirstCommitIsGoodSig"] == False]

def first_sig_summary(df, label):
    return {
        "Group":                 label,
        "n":                     len(df),
        "Avg Perceived Time":    df["Perceived_Time_Minutes"].mean().round(1),
        "GM Perceived Time":     round(gmean(df["Perceived_Time_Minutes"].dropna()), 1),
        "Median Perceived Time": df["Perceived_Time_Minutes"].median().round(1),
        "Avg SUS Score":         df["SUS_Score"].mean().round(1),
        "Avg Commits":           df["Commit_Count"].mean().round(1),
        "Avg Signed Commits":    df["Signed_Commit_Count"].mean().round(1),
        "Pct Used Web Flow":     f"{df['GitHub_Web_Flow_Used'].str.startswith('Yes', na=False).mean()*100:.1f}%",
    }

print(f"\n── 2b. Good First Sig vs. Not — Group Comparison ──")
comparison_2b = pd.DataFrame([
    first_sig_summary(good_first_df, "Good First Sig"),
    first_sig_summary(bad_first_df,  "No Good First Sig")
])
print(comparison_2b.set_index("Group"))

multi_df = final_df[final_df["Commit_Count"] > 1].copy()
multi_df["Signed_Ratio"] = multi_df["Signed_Commit_Count"] / multi_df["Commit_Count"]

print(f"\n── 3. Signed Commit Ratio (multi-commit users, n={len(multi_df)}) ──")
print(multi_df["Signed_Ratio"].describe().round(3).to_string())
fully_signed = (multi_df["Signed_Ratio"] == 1.0).sum()
none_signed  = (multi_df["Signed_Ratio"] == 0.0).sum()
print(f"  All commits signed (100%)  : {fully_signed} ({fully_signed/len(multi_df)*100:.1f}%)")
print(f"  No commits signed   (0%)   : {none_signed} ({none_signed/len(multi_df)*100:.1f}%)")

single_df = final_df[final_df["Commit_Count"] == 1]
t_single  = single_df["Perceived_Time_Minutes"].dropna()
t_multi   = multi_df["Perceived_Time_Minutes"].dropna()

print(f"\n── 4. Perceived Time (minutes): Single vs. Multi Commit ──")
print(f"  Single commit  — Mean: {t_single.mean():.1f}  Median: {t_single.median():.1f}  (n={len(t_single)})")
print(f"  Multi  commits — Mean: {t_multi.mean():.1f}  Median: {t_multi.median():.1f}  (n={len(t_multi)})")

from scipy.stats import mannwhitneyu
if len(t_single) > 1 and len(t_multi) > 1:
    stat, p = mannwhitneyu(t_single, t_multi, alternative="two-sided")
    print(f"  Mann-Whitney U p-value: {p:.3f} {'(significant)' if p < 0.05 else '(not significant)'}")

has_good = (final_df["Good_Signature_Count"] > 0).sum()
all_good = (final_df["Good_Signature_Count"] == final_df["Commit_Count"]).sum()

print(f"\n── 5. Good Signatures (all participants, n={total}) ──")
print(f"  At least one good signature : {has_good:>3}  ({has_good/total*100:.1f}%)")
print(f"  All commits have good sig   : {all_good:>3}  ({all_good/total*100:.1f}%)")

multi_df["GoodSig_Ratio"] = multi_df["Good_Signature_Count"] / multi_df["Commit_Count"]
print(f"\n── 6. Good Signature Ratio (multi-commit, n={len(multi_df)}) ──")
print(multi_df["GoodSig_Ratio"].describe().round(3).to_string())

webflow_mask = final_df["GitHub_Web_Flow_Used"].str.startswith("Yes", na=False)
webflow_n    = webflow_mask.sum()
no_webflow_n = (~webflow_mask).sum()

print(f"\n── 7. GitHub Web Flow Usage ──")
print(f"  Used Web Flow     : {webflow_n:>3}  ({webflow_n/total*100:.1f}%)")
print(f"  Did NOT use it    : {no_webflow_n:>3}  ({no_webflow_n/total*100:.1f}%)")

wf_df  = final_df[webflow_mask]
nwf_df = final_df[~webflow_mask]

def summarize(df, label):
    return {
        "Group":              label,
        "n":                  len(df),
        "Avg Commits":        df["Commit_Count"].mean().round(1),
        "Avg Signed Commits": df["Signed_Commit_Count"].mean().round(1),
        "Pct Any Good Sig":   f"{(df['Good_Signature_Count'] > 0).mean()*100:.1f}%",
        "Avg Perceived Time": df["Perceived_Time_Minutes"].mean().round(1),
    }

comparison = pd.DataFrame([summarize(wf_df, "Web Flow"), summarize(nwf_df, "No Web Flow")])
print(f"\n── 8. Web Flow vs. No Web Flow Comparison ──")
print(comparison.set_index("Group"))

low_sus  = final_df[final_df["SUS_Score"] < 70]
high_sus = final_df[final_df["SUS_Score"] >= 70]

print(f"\n── 9. Low SUS Score (<70) Analysis ──")
print(f"  Low SUS  (n={len(low_sus)}):  Mean={low_sus['SUS_Score'].mean():.1f}  "
      f"| Median Time={low_sus['Perceived_Time_Minutes'].median():.1f} min")
print(f"  High SUS (n={len(high_sus)}): Mean={high_sus['SUS_Score'].mean():.1f}  "
      f"| Median Time={high_sus['Perceived_Time_Minutes'].median():.1f} min")

for label, grp in [("Low SUS", low_sus), ("High SUS", high_sus)]:
    print(f"\n  Key Type Distribution — {label}:")
    print(grp["Submitted_Key_Type"].value_counts()
          .to_frame("Count")
          .assign(Pct=lambda x: (x["Count"]/x["Count"].sum()*100).round(1)))
    print(f"    Avg signed commits : {grp['Signed_Commit_Count'].mean():.1f}")
    print(f"    Pct with good sig  : {(grp['Good_Signature_Count'] > 0).mean()*100:.1f}%")
    print(f"    Pct used Web Flow  : {grp['GitHub_Web_Flow_Used'].str.startswith('Yes', na=False).mean()*100:.1f}%")


# %%
# %% [12] GROUP COMPARISON: Error vs. No-Error — ASQ, SUS, Time
from scipy.stats import mannwhitneyu, pointbiserialr, spearmanr

qualitative_report_errors    = ["P2","P4","P5","P6","P7","P8","P10","P11","P13","P14","P16","P17","P18","P19","P21","P22"]
no_qualitative_report_errors = ["P1","P3","P9","P12","P15","P20"]

final_df["Had_Errors"] = final_df["Participant"].isin(qualitative_report_errors)

err_df   = final_df[final_df["Had_Errors"] == True].copy()
noerr_df = final_df[final_df["Had_Errors"] == False].copy()

n_err    = len(qualitative_report_errors)
n_no_err = len(no_qualitative_report_errors)

print("=" * 65)
print(f"GROUP COMPARISON: Errors (n={n_err}) vs. No Errors (n={n_no_err})")
print("=" * 65)

def smart_mean(series, col):
    s = series.dropna()
    if col == "Perceived_Time_Minutes": return round(gmean(s), 2)
    return round(s.mean(), 2)

metrics = {
    "ASQ_Mean":               "ASQ Mean (1-7)",
    "SUS_Score":              "SUS Score (0-100)",
    "Perceived_Time_Minutes": "Perceived Time (min)",
}

rows_desc = []
for col, label in metrics.items():
    e  = err_df[col].dropna()
    ne = noerr_df[col].dropna()
    rows_desc.append({
        "Metric":          label,
        "Errors Mean":     smart_mean(e,  col),
        "Errors Median":   round(e.median(),  2),
        "NoErrors Mean":   smart_mean(ne, col),
        "NoErrors Median": round(ne.median(), 2),
    })

print("\n── 1. Descriptive Statistics ──")
print("   (Time uses geometric mean; ASQ and SUS use arithmetic mean)")
print(pd.DataFrame(rows_desc).set_index("Metric").to_string())

print("\n── 2. Mann-Whitney U Tests (two-sided) ──")
print(f"  {'Metric':<30} {'U':>8}  {'p':>8}  {'Sig (a=.05)':>12}")
print(f"  {'-'*30} {'-'*8}  {'-'*8}  {'-'*12}")
for col, label in metrics.items():
    e  = err_df[col].dropna()
    ne = noerr_df[col].dropna()
    if len(e) >= 2 and len(ne) >= 2:
        stat, p = mannwhitneyu(e, ne, alternative="two-sided")
        sig = "Yes *" if p < 0.05 else "No"
        print(f"  {label:<30} {stat:>8.1f}  {p:>8.3f}  {sig:>12}")

print("\n── 3. Point-Biserial Correlation — Had_Errors vs. Metric ──")
print(f"  {'Metric':<30} {'r_pb':>8}  {'p':>8}")
print(f"  {'-'*30} {'-'*8}  {'-'*8}")
for col, label in metrics.items():
    tmp = final_df[[col, "Had_Errors"]].dropna()
    if len(tmp) >= 4:
        r, p = pointbiserialr(tmp["Had_Errors"].astype(int), tmp[col])
        print(f"  {label:<30} {r:>8.3f}  {p:>8.3f}")

print("\n── 4. Spearman Correlations (error group only) ──")
spearman_pairs = [
    ("Commit_Count",           "ASQ_Mean",  "Commit count vs ASQ"),
    ("Commit_Count",           "SUS_Score", "Commit count vs SUS"),
    ("Signed_Commit_Count",    "ASQ_Mean",  "Signed commits vs ASQ"),
    ("Signed_Commit_Count",    "SUS_Score", "Signed commits vs SUS"),
    ("Perceived_Time_Minutes", "SUS_Score", "Perceived time vs SUS"),
    ("Perceived_Time_Minutes", "ASQ_Mean",  "Perceived time vs ASQ"),
]
print(f"  {'Pair':<35} {'rho':>8}  {'p':>8}")
print(f"  {'-'*35} {'-'*8}  {'-'*8}")
for c1, c2, label in spearman_pairs:
    tmp = err_df[[c1, c2]].dropna()
    if len(tmp) >= 4:
        rho, p = spearmanr(tmp[c1], tmp[c2])
        print(f"  {label:<35} {rho:>8.3f}  {p:>8.3f}")

print("\n── 5. ASQ Item Means by Group ──")
asq_items = ["Ease_of_Setting_Up", "Time", "Support_Information"]
tmp_asq   = final_df.merge(df[["Participant"] + asq_items], on="Participant", how="left")
print(f"  {'Item':<25} {'Errors':>10}  {'No Errors':>10}  {'Delta':>8}")
print(f"  {'-'*25} {'-'*10}  {'-'*10}  {'-'*8}")
for item in asq_items:
    e_mean  = tmp_asq[tmp_asq["Had_Errors"] == True][item].mean()
    ne_mean = tmp_asq[tmp_asq["Had_Errors"] == False][item].mean()
    print(f"  {item:<25} {e_mean:>10.2f}  {ne_mean:>10.2f}  {e_mean-ne_mean:>8.2f}")

print("\n── 6. Summary Table ──")
summary = pd.DataFrame({
    "Metric":        list(metrics.values()),
    "Error Mean":    [smart_mean(err_df[c],   c) for c in metrics],
    "NoErr Mean":    [smart_mean(noerr_df[c], c) for c in metrics],
    "Delta (Err-NoErr)": [round(smart_mean(err_df[c], c) - smart_mean(noerr_df[c], c), 2) for c in metrics],
}).set_index("Metric")
print(summary.to_string())
print("\nNote: Positive Delta = error group scored higher; Negative Delta = lower.")


# ===========================================================
# LONGITUDINAL USAGE ACROSS SEMESTER PROJECTS
# ===========================================================

# Canonical submission order for almost everyone:
# Project_1 -> Project_2 -> Project_3 -> Project_4
# (Exception: P14 submitted Project_2 last; sequence: Project_1 -> Project_3 -> Project_4 -> Project_2)
# (Exception: P22 only has data for Project_1 and Project_2; Project_3 and Project_4 archives missing)

part1_keys = final_df[["Participant", "Keys_Found_In_GitLog", "Extracted_Submitted_Fingerprint"]].rename(columns={
    "Keys_Found_In_GitLog":            "Part1_Keys_In_GitLog",
    "Extracted_Submitted_Fingerprint": "Part1_Submitted_Fingerprint"
})


# %%
# %% [13] LONGITUDINAL GIT LOG — FOUR PROJECTS
longitudinal_dir = Path("..") / "Data" / "longitudinal_usage_zipfiles"
projects         = ["Project_1", "Project_2", "Project_3", "Project_4"]  # chronological submission order

rows_longitudinal = []

for project in projects:
    project_dir = longitudinal_dir / project
    for arch in sorted(project_dir.iterdir()):
        if not arch.is_file() or not arch.stem.startswith("P"):
            continue
        suffixes = "".join(arch.suffixes)
        if arch.suffix not in {".zip", ".tgz"} and \
           not suffixes.endswith(".tar.gz") and \
           not suffixes.endswith(".tar.gzip"):
            continue

        participant = arch.name.split("_")[0]

        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            try:
                if suffixes.endswith(".tar.gzip"):
                    with tarfile.open(arch, "r:gz") as t:
                        t.extractall(td)
                else:
                    extract_archive(arch, td)
            except Exception as e:
                rows_longitudinal.append({"Participant": participant, "Project": project, "Status": f"ERROR: {e}"})
                continue

            repo = find_git_repo_root(td)
            if repo is None:
                rows_longitudinal.append({"Participant": participant, "Project": project, "Status": "NO_REPO_FOUND"})
                continue

            log_raw = run_git(repo, ["log", "--pretty=format:%H|%an|%ae|%G?|%GK|%ad", "--date=iso"])
            log_num = run_git(repo, ["rev-list", "--count", "HEAD"]).strip()
            p       = parse_git_log(log_raw)

            part1_row = part1_keys[part1_keys["Participant"] == participant]
            part1_fp  = str(part1_row["Part1_Submitted_Fingerprint"].values[0]).upper() if not part1_row.empty else None
            part1_git = str(part1_row["Part1_Keys_In_GitLog"].values[0]).upper()        if not part1_row.empty else None

            rows_longitudinal.append({
                "Participant":               participant,
                "Project":                  project,
                "Commit_Count":             int(log_num) if log_num.isdigit() else len(p["commit_dates"]),
                "Signed_Commit_Count":      p["signed_count"],
                "Good_Signature_Count":     p["good_sig_count"],
                "Unsigned_Commit_Count":    len(p["commit_dates"]) - p["signed_count"],
                "Signed_Ratio":             round(p["signed_count"] / len(p["commit_dates"]), 3) if p["commit_dates"] else None,
                "Signature_Status_Sequence": " -> ".join(reversed(p["all_statuses"])),
                "Has_Bad_Signatures":       "B" in p["all_statuses"],
                "Authors_Found_In_GitLog": f"({len(p['authors'])}) {'; '.join(sorted(p['authors']))}",
                "Keys_Found":               ",".join(sorted(p["keys_found"])) if p["keys_found"] else None,
                "Key_Count":                len(p["keys_found"]),
                "GitHub_Web_Flow_Used":     p["used_web_flow"],
                "Part1_Submitted_Fingerprint": part1_fp,
                "First_Commit_Time":        p["commit_dates"][-1] if p["commit_dates"] else None,
                "Last_Commit_Time":         p["commit_dates"][0]  if p["commit_dates"] else None,
            })

project_order   = {p: i for i, p in enumerate(projects)}
longitudinal_df = pd.DataFrame(rows_longitudinal)
longitudinal_df["Project_Order"] = longitudinal_df["Project"].map(project_order)
longitudinal_df = longitudinal_df.sort_values(["Participant", "Project_Order"]).drop(columns=["Project_Order"])
longitudinal_df = longitudinal_df.drop(columns=['Status'], errors='ignore')

longitudinal_df.to_csv('../Data/longitudinal_usage_zipfiles/longitudinal_git_signing.csv', index=False)

pd.set_option('display.max_rows', None)
pd.set_option('display.max_columns', None)
pd.set_option('display.width', None)
pd.set_option('display.max_colwidth', None)

# Signature Status Key:
# G (Good): Valid signature; trusted key
# U (Untrusted): Valid signature; unknown trust level
# E (Error): Signature found; public key missing
# N (None): No signature present
# B (Bad): Invalid signature; data mismatch
# X (Expired): Valid signature; key reached expiration
# Y (Expired Key): Valid signature; key is now expired
# R (Revoked): Valid signature; key was cancelled


# %%
print(f"Rows: {len(longitudinal_df)} | Participants: {longitudinal_df['Participant'].nunique()}")

# Load semester-end SUS
part2_df      = pd.read_csv(Path("..") / "Data" / "Assignment 2" / "assignment_2.csv")
part2_df.columns = part2_df.columns.str.strip()

sus_odd  = ['Semseter_Q1_Freq',    'Semseter_Q3_Easy',    'Semseter_Q5_Integ',
            'Semseter_Q7_Quick',   'Semseter_Q9_Confid']
sus_even = ['Semseter_Q2_Complex', 'Semseter_Q4_Support', 'Semseter_Q6_Inconsist',
            'Semseter_Q8_Cumber',  'Semseter_Q10_Learn']

def calculate_semester_sus(row):
    cols = sus_odd + sus_even
    if row[cols].isna().any(): return None
    return (sum(5 - row[c] for c in sus_odd) + sum(row[c] - 1 for c in sus_even)) * 2.5

part2_df['Semester_SUS'] = part2_df.apply(calculate_semester_sus, axis=1)
semester_sus = part2_df[['Participant', 'Semester_SUS']]

m, lo, hi = mean_ci(semester_sus['Semester_SUS'])
n  = semester_sus['Semester_SUS'].dropna().shape[0]
sd = semester_sus['Semester_SUS'].std()
print(f"Mean Semester SUS: {m} (95% CI [{lo}, {hi}], SD = {sd:.1f}, n = {n})")
display(semester_sus)

import matplotlib.pyplot as plt
import seaborn as sns

fig, axes = plt.subplots(1, 2, figsize=(6, 2), sharey=True, sharex=True)

datasets = [
    (final_df["SUS_Score"],        "First Setup\n(Start of Semester)", "teal"),
    (semester_sus["Semester_SUS"], "Semester-End\n(Longitudinal)",     "seagreen"),
]

for ax, (data, title, color) in zip(axes, datasets):
    sns.violinplot(x=data, inner="box", linewidth=3.2, color=color, ax=ax)
    sns.stripplot(x=data, ax=ax, color="black", size=3, alpha=0.5, jitter=True)
    ax.set_xlim(0, 100)
    ax.set_xlabel("SUS Score", fontsize=9)
    ax.set_title(title, fontsize=9)
    ax.tick_params(labelsize=10)

fig.savefig(str(Path("..") / "figures" / "sus_violin_comparison.pdf"), format="pdf", bbox_inches="tight")
plt.show()

# %%
longitudinal_df = longitudinal_df.merge(semester_sus, on="Participant", how="left")

summary = longitudinal_df.groupby("Participant").agg(
    Projects_Submitted = ("Commit_Count", "count"),
    Total_Commits      = ("Commit_Count",         "sum"),
    Total_Signed       = ("Signed_Commit_Count",  "sum"),
    Total_Unsigned     = ("Unsigned_Commit_Count", "sum"),
).reset_index()

summary["Overall_Signed_Ratio"]  = (summary["Total_Signed"] / summary["Total_Commits"]).round(3)
summary["Signed_All_Submitted"]  = summary["Total_Unsigned"] == 0

summary = summary.merge(semester_sus, on="Participant", how="left")

signed_all   = summary[summary["Signed_All_Submitted"]]
did_not_sign = summary[~summary["Signed_All_Submitted"]]
incomplete   = summary[summary["Projects_Submitted"] < 4]

print(f"Signed ALL commits (of what they submitted) : {len(signed_all)} / {len(summary)}")
print(f"\nSigned all      : {signed_all['Participant'].tolist()}")
print(f"Did NOT sign all: {did_not_sign['Participant'].tolist()}")

print(f"\n── Participants Who Did NOT Sign All Commits ──")
print(did_not_sign[["Participant","Total_Commits","Total_Signed",
                     "Total_Unsigned","Overall_Signed_Ratio"]].to_string(index=False))

print(f"\n── Participants With Incomplete Submissions (< 4 projects) ──")
print(incomplete[["Participant","Projects_Submitted"]].to_string(index=False))

from scipy.stats import mannwhitneyu

sus_signed     = signed_all["Semester_SUS"].dropna()
sus_not_signed = did_not_sign["Semester_SUS"].dropna()

print(f"\n── Semester SUS: Signed All vs. Did Not Sign All ──")
print(f"  Signed all   (n={len(sus_signed)}): Mean={sus_signed.mean():.1f}  Median={sus_signed.median():.1f}")
print(f"  Did not sign (n={len(sus_not_signed)}): Mean={sus_not_signed.mean():.1f}  Median={sus_not_signed.median():.1f}")

if len(sus_signed) >= 2 and len(sus_not_signed) >= 2:
    stat, p = mannwhitneyu(sus_signed, sus_not_signed, alternative="two-sided")
    print(f"\n  Mann-Whitney U = {stat:.1f}, p = {p:.3f}")
    print(f"  {'Statistically significant (p < 0.05)' if p < 0.05 else 'Not statistically significant (p >= 0.05)'}")
    n_total = len(sus_signed) + len(sus_not_signed)
    from scipy.stats import norm
    z = norm.ppf(1 - p/2)
    r_effect = z / np.sqrt(n_total)
    print(f"  Effect size r = {r_effect:.3f}")
else:
    print(f"\n  Too few participants for a reliable test (n={len(sus_not_signed)} did not sign all)")

commits_signed     = signed_all["Total_Commits"].dropna()
commits_not_signed = did_not_sign["Total_Commits"].dropna()

print(f"\n── Commit Count: Signed All vs. Did Not Sign All ──")
print(f"  Signed all   (n={len(commits_signed)}): Mean={commits_signed.mean():.1f}  Median={commits_signed.median():.1f}")
print(f"  Did not sign (n={len(commits_not_signed)}): Mean={commits_not_signed.mean():.1f}  Median={commits_not_signed.median():.1f}")

if len(commits_signed) >= 2 and len(commits_not_signed) >= 2:
    stat, p = mannwhitneyu(commits_signed, commits_not_signed, alternative="two-sided")
    print(f"\n  Mann-Whitney U = {stat:.1f}, p = {p:.3f}")
    print(f"  {'Statistically significant (p < 0.05)' if p < 0.05 else 'Not statistically significant (p >= 0.05)'}")
    n_total = len(commits_signed) + len(commits_not_signed)
    z = norm.ppf(1 - p/2)
    r_effect = z / np.sqrt(n_total)
    print(f"  Effect size r = {r_effect:.3f}")


# ===========================================================
# PART 2
# ===========================================================

import pandas as pd
import numpy as np
from scipy import stats
from scipy.stats import gmean

# 2nd Device Setup
part2_df['ASQ_S1'] = part2_df[['2nd_device_Ease', '2nd_device_Time', '2nd_device_Support']].mean(axis=1)

overall_mean_asq_s1   = part2_df['ASQ_S1'].mean()
overall_gmean_time_s1 = gmean(part2_df['2nd_device_reported_time'].dropna())

print("--- 2nd Device Setup ---")
print(f"Mean ASQ: {overall_mean_asq_s1:.2f}")
print(f"Geometric Mean Time: {overall_gmean_time_s1:.2f} min")

print("\n=== Scores by Migration Approach ===")
for name, group in part2_df.groupby('migration_approach'):
    vals = group['ASQ_S1'].dropna()
    print(f"  {name}: n={len(vals)}, mean={vals.mean():.2f}, median={vals.median():.2f}, std={vals.std():.2f}")

new_key = part2_df[part2_df['migration_approach'] == 'new-key']['ASQ_S1'].dropna()
copy    = part2_df[part2_df['migration_approach'] == 'copy']['ASQ_S1'].dropna()
u_stat, p_val = stats.mannwhitneyu(new_key, copy, alternative='two-sided')
print(f"  Mann-Whitney U={u_stat:.1f}, p={p_val:.3f} {'*' if p_val < 0.05 else '(not significant)'}")
n_total = len(new_key) + len(copy)
z = norm.ppf(1 - p_val/2)
print(f"  Effect size r = {z / np.sqrt(n_total):.3f}")

print("\n--- Geometric Mean Time by Migration Approach ---")
for name, group in part2_df.groupby('migration_approach'):
    vals = group['2nd_device_reported_time'].dropna()
    print(f"  {name}: {gmean(vals):.2f} min")

new_key_time = part2_df[part2_df['migration_approach'] == 'new-key']['2nd_device_reported_time'].dropna()
copy_time    = part2_df[part2_df['migration_approach'] == 'copy']['2nd_device_reported_time'].dropna()
u_stat, p_val = stats.mannwhitneyu(new_key_time, copy_time, alternative='two-sided')
print(f"  Mann-Whitney U={u_stat:.1f}, p={p_val:.3f} {'*' if p_val < 0.05 else '(not significant)'}")
n_total = len(new_key_time) + len(copy_time)
z = norm.ppf(1 - p_val/2)
print(f"  Effect size r = {z / np.sqrt(n_total):.3f}")


# ===========================================================
# PART 2 — Analyzing Commit History
# ===========================================================

part2_df['ASQ_S2'] = part2_df[['Analyzing_commits_Ease', 'Analyzing_commits_Time', 'Analyzing_commits_Support']].mean(axis=1)

overall_mean_asq_s2   = part2_df['ASQ_S2'].mean()
overall_gmean_time_s2 = gmean(part2_df['Analyzing_commits_reported_time'].dropna())

print("\n--- Analyzing Commit History ---")
print(f"Mean ASQ: {overall_mean_asq_s2:.2f}")
print(f"Geometric Mean Time: {overall_gmean_time_s2:.2f} min")

# %%
score_col = 'Score (identifying malicious commit)/13'

def significance_label(p):
    if p < 0.05:
        return "statistically significant (p < 0.05)"
    else:
        return "not statistically significant (p >= 0.05)"

# --- ANALYSIS 1: TIME vs SCORE ---
dropped = part2_df[part2_df['Analyzing_commits_reported_time'].isna()][
    ['Participant', 'Analyzing_commits_reported_time', score_col]
]
df_clean = part2_df[['Analyzing_commits_reported_time', score_col]].dropna()
time  = df_clean['Analyzing_commits_reported_time']
score = df_clean[score_col]

pearson_r,  pearson_p  = stats.pearsonr(time, score)
spearman_r, spearman_p = stats.spearmanr(time, score)

print("\n" + "="*50)
print("Is there a relationship between time taken to analyze commits and number of problematic commits identified?")
print("="*50)
print(f"Dropped rows:\n{dropped.to_string(index=False)}")
print(f"\nN (after dropping NaN): {len(df_clean)}")
print(f"Pearson  r = {pearson_r:.3f}, p = {pearson_p:.3f} -- {significance_label(pearson_p)}")
print(f"Spearman r = {spearman_r:.3f}, p = {spearman_p:.3f} -- {significance_label(spearman_p)}")

# --- ANALYSIS 2: ASQ_S2 vs SCORE ---
asq_col = 'ASQ_S2'
dropped_asq  = part2_df[part2_df[asq_col].isna()][['Participant', asq_col, score_col]]
df_asq_clean = part2_df[[asq_col, score_col]].dropna()
asq_vals      = df_asq_clean[asq_col]
score_vals_asq = df_asq_clean[score_col]

pearson_r_asq,  pearson_p_asq  = stats.pearsonr(asq_vals, score_vals_asq)
spearman_r_asq, spearman_p_asq = stats.spearmanr(asq_vals, score_vals_asq)

print("\n" + "="*50)
print(f"Is there a relationship between {asq_col} (task rating) and number of problematic commits identified?")
print("="*50)
print(f"Dropped rows:\n{dropped_asq.to_string(index=False)}")
print(f"\nN (valid pairs): {len(df_asq_clean)}")
print(f"Pearson  r = {pearson_r_asq:.3f}, p = {pearson_p_asq:.3f} -- {significance_label(pearson_p_asq)}")
print(f"Spearman r = {spearman_r_asq:.3f}, p = {spearman_p_asq:.3f} -- {significance_label(spearman_p_asq)}")

# %%
part2_df.columns = part2_df.columns.str.strip()
score_col = 'Score (identifying malicious commit)/13'

print("=" * 60)
print("How Participants Identified Commits")
print("=" * 60)

# 1. STRATEGY COUNTS
print("\n── 1. Strategy Counts ──")
strategy_counts = part2_df['strategy'].value_counts()
print(strategy_counts)
n_cli    = (part2_df['strategy'] == 'cli').sum()
n_web    = (part2_df['strategy'] == 'web').sum()
n_cliweb = (part2_df['strategy'] == 'cli+web').sum()
n_none   = (part2_df['strategy'] == 'none').sum()
print(f"\nCLI only  : n={n_cli}")
print(f"Web only  : n={n_web}")
print(f"CLI + Web : n={n_cliweb}")
print(f"None      : n={n_none}")

# 2. MEAN SCORE BY STRATEGY
print("\n── 2. Mean Score by Strategy ──")
strategy_scores = part2_df.groupby('strategy')[score_col].mean().round(2)
print(strategy_scores)
print(f"\nCLI mean      : {part2_df[part2_df['strategy']=='cli'][score_col].mean():.2f}")
print(f"Web mean      : {part2_df[part2_df['strategy']=='web'][score_col].mean():.2f}")
print(f"CLI+Web mean  : {part2_df[part2_df['strategy']=='cli+web'][score_col].mean():.2f}")

# 3. CONFIGURED vs NOT — MEAN SCORES
print("\n── 3. Configured vs Not Configured ──")
configured     = part2_df[part2_df['configured_signers'] == True]
not_configured = part2_df[part2_df['configured_signers'] == False]
print(f"n configured     : {len(configured)}")
print(f"n not configured : {len(not_configured)}")
print(f"Mean configured     : {configured[score_col].mean():.2f}")
print(f"Mean not configured : {not_configured[score_col].mean():.2f}")

from scipy.stats import mannwhitneyu, norm
cfg_scores     = configured[score_col].dropna()
not_cfg_scores = not_configured[score_col].dropna()
if len(cfg_scores) >= 2 and len(not_cfg_scores) >= 2:
    u_stat, p_val = mannwhitneyu(cfg_scores, not_cfg_scores, alternative='two-sided')
    n_total = len(cfg_scores) + len(not_cfg_scores)
    z = norm.ppf(1 - p_val/2)
    r_effect = z / np.sqrt(n_total)
    print(f"\n  Mann-Whitney U = {u_stat:.1f}, p = {p_val:.3f}  {'*' if p_val < 0.05 else '(not significant)'}")
    print(f"  Effect size r = {r_effect:.3f}")
    print(f"  {'Statistically significant (p < 0.05)' if p_val < 0.05 else 'Not statistically significant'}")

# 4. SIGNERS FILE ATTEMPT STATS
print("\n── 4. allowedSignersFile Attempt Stats ──")
n_attempted  = part2_df['signers_attempt'].sum()
n_configured = part2_df['configured_signers'].sum()
n_failed     = n_attempted - n_configured
failure_rate = n_failed / n_attempted * 100
print(f"Attempted  : {n_attempted}")
print(f"Succeeded  : {n_configured}")
print(f"Failed     : {n_failed}")
print(f"Failure rate: {failure_rate:.0f}%")

# 5. CONFUSED PRIVATE/PUBLIC KEYS
print("\n── 5. Key Confusion ──")
n_confused = part2_df['confused_private_public'].sum()
print(f"Confused private/public keys : {n_confused}")
print("Participants:", list(part2_df[part2_df['confused_private_public']==True]['Participant']))

# 6. GAVE UP — COUNT AND MEAN SCORE
print("\n── 6. Gave Up Stats ──")
gave_up = part2_df[part2_df['gave_up'] == True]
did_not = part2_df[part2_df['gave_up'] == False]
print(f"Gave up     : n={len(gave_up)}")
print(f"Mean score (gave up)     : {gave_up[score_col].mean():.1f}")
print(f"Mean score (did not)     : {did_not[score_col].mean():.2f}")
print("Participants who gave up:", list(gave_up['Participant']))

gave_up_scores = gave_up[score_col].dropna()
did_not_scores = did_not[score_col].dropna()
if len(gave_up_scores) >= 2 and len(did_not_scores) >= 2:
    u_stat, p_val = mannwhitneyu(gave_up_scores, did_not_scores, alternative='two-sided')
    n_total = len(gave_up_scores) + len(did_not_scores)
    z = norm.ppf(1 - p_val/2)
    print(f"  Mann-Whitney U = {u_stat:.1f}, p = {p_val:.3f}")
    print(f"  Effect size r = {z / np.sqrt(n_total):.3f}")

# 7. CODE CONTENT REVIEWERS
print("\n── 7. Code Content Review Effect ──")
reviewers     = part2_df[part2_df['used_grep_content'] == True]
non_reviewers = part2_df[part2_df['used_grep_content'] == False]
print(f"Content reviewers     : n={len(reviewers)}")
print(f"Mean score (reviewers)     : {reviewers[score_col].mean():.1f}")
print(f"Mean score (non-reviewers) : {non_reviewers[score_col].mean():.1f}")
print("Participants who reviewed content:", list(reviewers['Participant']))

# %%
print(pd.merge(part2_df[['Participant','Score (identifying malicious commit)/13']], final_df[['Participant','Submitted_Key_Type']], on='Participant').groupby('Submitted_Key_Type')['Score (identifying malicious commit)/13'].agg(['mean','median','count']).round(2))

merged_df = pd.merge(
    part2_df[['Participant', 'Score (identifying malicious commit)/13']],
    final_df[['Participant', 'Submitted_Key_Type']],
    on='Participant'
)

gpg_scores = merged_df[merged_df['Submitted_Key_Type'] == 'GPG']['Score (identifying malicious commit)/13']
ssh_scores = merged_df[merged_df['Submitted_Key_Type'] == 'SSH']['Score (identifying malicious commit)/13']

stat, p_value = mannwhitneyu(gpg_scores, ssh_scores, alternative='two-sided')

print("--- Statistical Test Results ---")
print(f"Mann-Whitney U Statistic: {stat}")
print(f"P-value: {p_value:.4f}")

if p_value < 0.05:
    print("Result: Significant difference found between GPG and SSH groups.")
else:
    print("Result: No statistically significant difference found (p >= 0.05).")
