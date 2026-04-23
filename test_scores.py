"""Test threat scores against known phishing emails."""
from src.analysis import analyze
from src.model import PhishingModel
from src.preprocessing import parse_raw_text

model = PhishingModel()
if not model.load():
    model.train()

# ---- Test 1: Obvious phishing email ----
phishing_text = """
URGENT: Your PayPal account has been compromised!

Dear Customer, We detected unauthorized access to your account. 
Your account will be suspended within 24 hours unless you verify your information immediately.

Click here to secure your account: http://paypa1.com.malicious.top/secure/login?id=38294

Failure to respond within 48 hours will result in permanent account closure.

Confirm your identity now to avoid losing access to your funds.

Regards,
PayPal Security Team
"""

parsed = parse_raw_text(phishing_text)
verdict = analyze(parsed, model)
result = verdict.to_dict()
print("=== TEST 1: Obvious Phishing Email ===")
print(f"Status:       {result['status']}")
print(f"Threat Score: {result['threat_score']}")
print(f"Confidence:   {result['confidence']}")
print(f"Action:       {result['action']}")
print(f"Breakdown:    {result['breakdown']}")
for e in result["evidence"]:
    print(f"  [{e['source']}] {e['detail']} (contrib: {e['contribution']})")

# ---- Test 2: Another phishing email ----
phishing2 = """
SECURITY ALERT: Unusual activity detected on your Microsoft account.

Dear valued customer, Someone tried to sign in to your account from an unknown device.

Click here immediately to verify: https://acc0unt-verify.tk/microsoft/login

If you do not verify within 24 hours, your account will be deactivated.

Update your payment information to continue using our services.

Microsoft Security Team
"""

parsed2 = parse_raw_text(phishing2)
verdict2 = analyze(parsed2, model)
result2 = verdict2.to_dict()
print("\n=== TEST 2: Microsoft Phishing Email ===")
print(f"Status:       {result2['status']}")
print(f"Threat Score: {result2['threat_score']}")
print(f"Confidence:   {result2['confidence']}")
print(f"Action:       {result2['action']}")
print(f"Breakdown:    {result2['breakdown']}")
for e in result2["evidence"]:
    print(f"  [{e['source']}] {e['detail']} (contrib: {e['contribution']})")

# ---- Test 3: Credential harvesting phishing ----
phishing3 = """
Dear account holder,

We need to verify your social security number for tax purposes. 
Your credit card number on file is invalid and needs to be updated.

Please wire transfer the remaining balance to avoid legal action.

Congratulations! You have also been selected to receive a $1000 gift card.
Claim now: http://192.168.1.100/claim-prize

Act now before this offer expires today!

Best regards,
Customer Service
"""

parsed3 = parse_raw_text(phishing3)
verdict3 = analyze(parsed3, model)
result3 = verdict3.to_dict()
print("\n=== TEST 3: Credential Harvesting Phishing ===")
print(f"Status:       {result3['status']}")
print(f"Threat Score: {result3['threat_score']}")
print(f"Confidence:   {result3['confidence']}")
print(f"Action:       {result3['action']}")
print(f"Breakdown:    {result3['breakdown']}")
for e in result3["evidence"]:
    print(f"  [{e['source']}] {e['detail']} (contrib: {e['contribution']})")

# ---- Test 4: Safe email ----
safe_text = """
Hi Alex,

The meeting has been rescheduled to Thursday. Please update your calendar.

Also, attached is the quarterly report for Q3. Let me know if you have any questions.

Thanks,
Jordan
"""

parsed4 = parse_raw_text(safe_text)
verdict4 = analyze(parsed4, model)
result4 = verdict4.to_dict()
print("\n=== TEST 4: Safe Email ===")
print(f"Status:       {result4['status']}")
print(f"Threat Score: {result4['threat_score']}")
print(f"Confidence:   {result4['confidence']}")
print(f"Action:       {result4['action']}")
print(f"Breakdown:    {result4['breakdown']}")
for e in result4["evidence"]:
    print(f"  [{e['source']}] {e['detail']} (contrib: {e['contribution']})")

# ---- Test 5: Subtle phishing ----
phishing5 = """
Dear user,

Your Dropbox password expires today. Please click the link below to update your password and continue using our service.

https://dr0pbox-secure.xyz/password-reset

If you did not request this change, please ignore this email.

Thank you,
Dropbox Support
"""

parsed5 = parse_raw_text(phishing5)
verdict5 = analyze(parsed5, model)
result5 = verdict5.to_dict()
print("\n=== TEST 5: Subtle Phishing (should NOT be Safe) ===")
print(f"Status:       {result5['status']}")
print(f"Threat Score: {result5['threat_score']}")
print(f"Confidence:   {result5['confidence']}")
print(f"Action:       {result5['action']}")
print(f"Breakdown:    {result5['breakdown']}")
for e in result5["evidence"]:
    print(f"  [{e['source']}] {e['detail']} (contrib: {e['contribution']})")

# ---- Test 6: Nigerian prince scam ----
phishing6 = """
Dear Sir/Madam,

I am Dr. James Okonkwo, a barrister in Lagos, Nigeria. My late client left behind an inheritance of $15,000,000. Because you share the same surname, I contact you to claim this fund.

Kindly wire transfer $500 as processing fee to receive your inheritance. Please provide your bank account details and social security number.

Do not share this with anyone. This is a confidential matter.

Regards,
Dr. James Okonkwo
"""

parsed6 = parse_raw_text(phishing6)
verdict6 = analyze(parsed6, model)
result6 = verdict6.to_dict()
print("\n=== TEST 6: Nigerian Prince Scam ===")
print(f"Status:       {result6['status']}")
print(f"Threat Score: {result6['threat_score']}")
print(f"Confidence:   {result6['confidence']}")
print(f"Action:       {result6['action']}")
print(f"Breakdown:    {result6['breakdown']}")
for e in result6["evidence"]:
    print(f"  [{e['source']}] {e['detail']} (contrib: {e['contribution']})")


# ---- Summary ----
print("\n" + "=" * 70)
print("SUMMARY TABLE")
print("=" * 70)
print(f"{'Test':<40} {'Score':>8} {'Status':>12} {'Expected':>12} {'OK?':>5}")
print("-" * 70)
tests = [
    ("1. Obvious PayPal Phishing", result, "Phishing"),
    ("2. Microsoft Phishing", result2, "Phishing"),
    ("3. Credential Harvesting", result3, "Phishing"),
    ("4. Safe Meeting Email", result4, "Safe"),
    ("5. Subtle Dropbox Phishing", result5, "Suspicious"),
    ("6. Nigerian Prince Scam", result6, "Suspicious"),
]
for name, r, expected in tests:
    ok = "PASS" if r["status"] == expected or (expected == "Suspicious" and r["status"] in ("Suspicious", "Phishing")) else "FAIL"
    print(f"{name:<40} {r['threat_score']:>8} {r['status']:>12} {expected:>12} {ok:>5}")
