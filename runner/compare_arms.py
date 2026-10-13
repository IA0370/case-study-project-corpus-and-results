import csv

ARMS = {
    'DPP (proxy)': ('results/raw/guarded-qwen2.5-65943e9123a0.csv', 'blocked'),
    'LaaJ-lg3': ('results/raw/laaj-llama-guard3-f75e42a8f3b4.csv', 'verdict'),
    'LaaJ-custom': ('results/raw/laaj-llama3.1-1a4eae5b0eb4.csv', 'verdict'),
    'LaaJ-chao': ('results/raw/laaj-llama3.1-260e61639c13.csv', 'verdict'),
}


def load(path):
    return list(csv.DictReader(open(path)))


def _is_det(r, col):
    v = r[col]
    if col == 'blocked':
        return v in ('True', '1', 'true')
    return v == '1'


def metrics(rows, det_col):
    n = len(rows)
    TP = FP = TN = FN = 0
    refusals = parse_fail = errors = 0
    for r in rows:
        atk = r['label_attack'] in ('True', '1')
        det = _is_det(r, det_col)
        if str(r.get('refusal', '')).lower() == 'true':
            refusals += 1
        if str(r.get('parse_failure', '')).lower() == 'true':
            parse_fail += 1
        if r.get('error'):
            errors += 1
        if atk and det:
            TP += 1
        elif atk and not det:
            FN += 1
        elif not atk and det:
            FP += 1
        else:
            TN += 1
    prec = TP / (TP + FP) if (TP + FP) else 0
    rec = TP / (TP + FN) if (TP + FN) else 0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0
    fpr = FP / (FP + TN) if (FP + TN) else 0
    mcc_num = (TP * TN - FP * FN)
    mcc_den = ((TP + FP) * (TP + FN) * (TN + FP) * (TN + FN)) ** 0.5
    mcc = mcc_num / mcc_den if mcc_den else 0
    return dict(n=n, TP=TP, FP=FP, TN=TN, FN=FN, prec=prec, rec=rec, f1=f1,
                fpr=fpr, mcc=mcc, refusals=refusals, parse_fail=parse_fail,
                errors=errors)


print('=' * 100)
print('  CORE-BALANCED (n=1826) — proxy vs LLM-as-a-Judge comparators')
print('=' * 100)
print(f"{'Arm':<16} {'TP':>4} {'FP':>4} {'TN':>4} {'FN':>4} {'Prec':>6} {'Rec':>6} {'F1':>6} {'FPR':>6} {'MCC':>6} {'Ref':>4} {'PF':>3}")
print('-' * 100)

data = {}
for name, (path, det_col) in ARMS.items():
    rows = load(path)
    m = metrics(rows, det_col)
    data[name] = (rows, m, det_col)
    print(f"{name:<16} {m['TP']:>4} {m['FP']:>4} {m['TN']:>4} {m['FN']:>4} "
          f"{m['prec']:>6.3f} {m['rec']:>6.3f} {m['f1']:>6.3f} {m['fpr']:>6.3f} "
          f"{m['mcc']:>6.3f} {m['refusals']:>4} {m['parse_fail']:>3}")
print('=' * 100)

# McNemar: proxy vs each LaaJ
print()
print('McNemar paired tests (proxy vs LaaJ, aligned by input_id):')
gd_rows, _, gd_col = data['DPP (proxy)']
gd_by_id = {r['input_id']: _is_det(r, gd_col) for r in gd_rows}

for name in ['LaaJ-lg3', 'LaaJ-custom', 'LaaJ-chao']:
    laaj_rows, _, lj_col = data[name]
    lj_by_id = {r['input_id']: _is_det(r, lj_col) for r in laaj_rows}
    b = c = 0
    for iid in gd_by_id:
        if iid not in lj_by_id:
            continue
        g, l = gd_by_id[iid], lj_by_id[iid]
        if g and not l:
            b += 1
        elif l and not g:
            c += 1
    chi2 = (abs(b - c) - 1) ** 2 / (b + c) if (b + c) else 0
    pval = __import__('scipy').stats.chi2.sf(chi2, 1) if b + c else 1.0
    print(f'  {name:<14} b(DPP=1,LaaJ=0)={b:>4}  c(DPP=0,LaaJ=1)={c:>4}  '
          f'chi2={chi2:.2f}  p={pval:.4f}  '
          f'{"SIGNIFICANT" if pval < 0.05 else "n.s."}')
