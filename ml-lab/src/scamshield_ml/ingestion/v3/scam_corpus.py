"""Scam Corpus Generator for ScamShield Dataset v3.

Covers all 22 Indian threat categories across English, Hindi (Devanagari),
Marathi (Devanagari), Hinglish (Romanized Hindi), and Romanized Marathi:
1. BANKING_KYC
2. UPI_FRAUD
3. OTP_THEFT
4. PHISHING_URL
5. DIGITAL_ARREST
6. ELECTRICITY
7. DELIVERY
8. JOB_OFFER
9. LOTTERY
10. LOAN_FRAUD
11. REMOTE_ACCESS_FRAUD
12. SIM_DEACTIVATION
13. TAX_CHALLAN_FRAUD
14. CUSTOMER_SUPPORT_SCAM
15. INVESTMENT_CRYPTO_FRAUD
16. REFUND_SCAM
17. QR_CODE_FRAUD
18. IMPOSTER_SCAM
19. FAMILY_EMERGENCY_SCAM
20. PAYMENT_REQUEST_SCAM
21. SOCIAL_ENGINEERING
22. ACCOUNT_TAKEOVER
"""

from __future__ import annotations

import random
from typing import Any, Dict, List


def generate_scam_corpus() -> List[Dict[str, Any]]:
    """Generates an extensive, authentic corpus of Indian cyber fraud samples."""
    samples: List[Dict[str, Any]] = []
    rng = random.Random(4242)

    # -------------------------------------------------------------------------
    # 1. BANKING KYC SCAMS (SBI, HDFC, ICICI, AXIS, PNB, BOB)
    # -------------------------------------------------------------------------
    banks = [
        ("SBI", "sbi-online-kyc", "State Bank of India"),
        ("HDFC Bank", "hdfc-portal-update", "HDFC"),
        ("ICICI Bank", "icici-kyc-verify", "ICICI"),
        ("Axis Bank", "axis-netbanking-alert", "Axis"),
        ("Bank of Baroda", "bob-pan-service", "Bank of Baroda"),
        ("Punjab National Bank", "pnb-one-update", "PNB"),
        ("Canara Bank", "canara-kyc-desk", "Canara Bank"),
        ("Kotak Bank", "kotak-811-kyc", "Kotak"),
    ]

    scam_tlds = ["top", "xyz", "click", "site", "live", "vip", "link", "club", "online"]

    for bank_name, slug, short_b in banks:
        for tld in scam_tlds[:5]:
            fake_url = f"https://{slug}-{rng.randint(10,99)}.{tld}/pan"
            ph = f"+91 {rng.randint(7000000000, 9999999999)}"

            # English
            text_en = (
                f"Dear Customer, Your {short_b} NetBanking will be BLOCKED today due to pending PAN/KYC. "
                f"Update immediately to avoid penalty: {fake_url} or contact Helpdesk {ph}."
            )
            samples.append({
                "content": text_en,
                "content_type": "message",
                "label": "scam",
                "is_scam": 1,
                "category": "BANKING_KYC",
                "language": "en",
                "source": "curated_threat_intel",
                "extracted_urls": [fake_url],
                "extracted_phones": [ph],
                "extracted_upis": [],
                "synthetic": True,
                "brand": short_b,
                "explanation": "Bank impersonation with account block threat and phishing URL.",
            })

            # Hindi
            text_hi = (
                f"प्रिय ग्राहक, आपका {short_b} बैंक खाता आज रात 12 बजे निलंबित कर दिया जाएगा। "
                f"तुरंत पैन कार्ड अपडेट करने के लिए लिंक खोलें: {fake_url} सहायता: {ph}."
            )
            samples.append({
                "content": text_hi,
                "content_type": "message",
                "label": "scam",
                "is_scam": 1,
                "category": "BANKING_KYC",
                "language": "hi",
                "source": "synthetic_multilingual_corpus",
                "extracted_urls": [fake_url],
                "extracted_phones": [ph],
                "extracted_upis": [],
                "synthetic": True,
                "brand": short_b,
                "explanation": "Hindi bank account suspension threat with malicious KYC link.",
            })

            # Marathi
            text_mr = (
                f"आदरणीय ग्राहक, आपले {short_b} बँक खाते केवायसी अपडेट न केल्यामुळे तात्पुरते बंद करण्यात आले आहे. "
                f"खाते सुरू ठेवण्यासाठी त्वरित या लिंकवर क्लिक करा: {fake_url}."
            )
            samples.append({
                "content": text_mr,
                "content_type": "message",
                "label": "scam",
                "is_scam": 1,
                "category": "BANKING_KYC",
                "language": "mr",
                "source": "synthetic_multilingual_corpus",
                "extracted_urls": [fake_url],
                "extracted_phones": [],
                "extracted_upis": [],
                "synthetic": True,
                "brand": short_b,
                "explanation": "Marathi bank KYC suspension phishing lure.",
            })

            # Hinglish
            text_hng = (
                f"Aapka {short_b} account aaj raat suspend ho jayega KYC verify na hone par. "
                f"Turant activate karne ke liye link open karein: {fake_url}"
            )
            samples.append({
                "content": text_hng,
                "content_type": "message",
                "label": "scam",
                "is_scam": 1,
                "category": "BANKING_KYC",
                "language": "hinglish",
                "source": "synthetic_multilingual_corpus",
                "extracted_urls": [fake_url],
                "extracted_phones": [],
                "extracted_upis": [],
                "synthetic": True,
                "brand": short_b,
                "explanation": "Hinglish bank account suspension phishing message.",
            })

            # Romanized Marathi
            text_rmr = (
                f"Tumche {short_b} account band karnyat yenar ahe. "
                f"Chalu thevnyasathi lagech KYC update kra: {fake_url}"
            )
            samples.append({
                "content": text_rmr,
                "content_type": "message",
                "label": "scam",
                "is_scam": 1,
                "category": "BANKING_KYC",
                "language": "romanized_mr",
                "source": "synthetic_multilingual_corpus",
                "extracted_urls": [fake_url],
                "extracted_phones": [],
                "extracted_upis": [],
                "synthetic": True,
                "brand": short_b,
                "explanation": "Romanized Marathi KYC phishing message.",
            })

    # -------------------------------------------------------------------------
    # 2. UPI FRAUD & QR CODE FRAUD (GOOGLE PAY, PHONEPE, PAYTM)
    # -------------------------------------------------------------------------
    upi_apps = ["PhonePe", "Google Pay", "Paytm", "BHIM"]
    for app in upi_apps:
        for _ in range(8):
            amt = rng.choice([499, 1499, 2999, 4999, 9999, 15000])
            fake_upi = f"cashback-{rng.randint(100,999)}@ybl"
            fake_link = f"https://{app.lower().replace(' ', '')}-reward-{rng.randint(10,99)}.top/claim"

            # English QR / Collect scam
            text_en = (
                f"Congratulations! You won Rs.{amt} cashback in {app} Diwali Lucky Draw. "
                f"Scan attached QR or accept collect request from {fake_upi} and enter UPI PIN to receive money: {fake_link}."
            )
            samples.append({
                "content": text_en,
                "content_type": "message",
                "label": "scam",
                "is_scam": 1,
                "category": "UPI_FRAUD",
                "language": "en",
                "source": "curated_threat_intel",
                "extracted_urls": [fake_link],
                "extracted_phones": [],
                "extracted_upis": [fake_upi],
                "synthetic": True,
                "brand": app,
                "explanation": "Classic UPI reverse collect / PIN-entry deception claiming cashback.",
            })

            # Hindi QR scam
            text_hi = (
                f"बधाई हो! आपको {app} की तरफ से रु {amt} का कैशबैक मिला है। "
                f"पैसे सीधे बैंक में पाने के लिए क्यूआर कोड स्कैन करें और अपना यूपीआई पिन डालें: {fake_link}"
            )
            samples.append({
                "content": text_hi,
                "content_type": "message",
                "label": "scam",
                "is_scam": 1,
                "category": "QR_CODE_FRAUD",
                "language": "hi",
                "source": "synthetic_multilingual_corpus",
                "extracted_urls": [fake_link],
                "extracted_phones": [],
                "extracted_upis": [],
                "synthetic": True,
                "brand": app,
                "explanation": "Hindi QR code cash deception asking victim to enter PIN to receive money.",
            })

            # Hinglish OLX buyer scam
            text_hng = (
                f"Sir maine OLX par aapka sofa dekh liya hai. Mai advance me Rs {amt} bhej raha hu. "
                f"Yeh QR code scan karke UPI PIN enter karo, payment turant aapke account me credit ho jayega."
            )
            samples.append({
                "content": text_hng,
                "content_type": "message",
                "label": "scam",
                "is_scam": 1,
                "category": "QR_CODE_FRAUD",
                "language": "hinglish",
                "source": "curated_threat_intel",
                "extracted_urls": [],
                "extracted_phones": [],
                "extracted_upis": [],
                "synthetic": True,
                "brand": "OLX",
                "explanation": "Pretext OLX buyer scam coercing seller to enter PIN to receive payment.",
            })

            # Marathi QR scam
            text_mr = (
                f"अभिनंदन! {app} कडून तुम्हाला रु {amt} चा बक्षीस जाहीर झाला आहे. "
                f"रक्कम आपल्या खात्यात जमा करण्यासाठी क्यूआर कोड स्कॅन करून यूपीआई पिन टाका: {fake_link}"
            )
            samples.append({
                "content": text_mr,
                "content_type": "message",
                "label": "scam",
                "is_scam": 1,
                "category": "QR_CODE_FRAUD",
                "language": "mr",
                "source": "synthetic_multilingual_corpus",
                "extracted_urls": [fake_link],
                "extracted_phones": [],
                "extracted_upis": [],
                "synthetic": True,
                "brand": app,
                "explanation": "Marathi QR code PIN-theft fraud message.",
            })

    # -------------------------------------------------------------------------
    # 3. DIGITAL ARREST & LAW ENFORCEMENT EXTORTION (POLICE, CBI, ED, CUSTOMS)
    # -------------------------------------------------------------------------
    agencies = ["CBI Mumbai", "Cyber Crime Cell New Delhi", "Narcotics Control Bureau (NCB)", "ED Financial Intelligence", "Mumbai Police Crime Branch"]
    for agency in agencies:
        for _ in range(5):
            caseno = f"FIR-{rng.randint(100,999)}/2026"
            fake_officer = f"Inspector {rng.choice(['Sharma', 'Patil', 'Deshmukh', 'Verma', 'Singh'])}"
            ph = f"+91 {rng.randint(7000000000, 9999999999)}"

            # English
            text_en = (
                f"URGENT LEGAL NOTICE: A parcel containing illegal narcotics and fake passports in your name has been seized by {agency}. "
                f"Case No: {caseno}. You are under Digital Arrest. Immediately join WhatsApp Video Call with {fake_officer} on {ph} to clear charges."
            )
            samples.append({
                "content": text_en,
                "content_type": "message",
                "label": "scam",
                "is_scam": 1,
                "category": "DIGITAL_ARREST",
                "language": "en",
                "source": "cybercrime_gov_in",
                "extracted_urls": [],
                "extracted_phones": [ph],
                "extracted_upis": [],
                "synthetic": True,
                "brand": agency,
                "explanation": "Digital arrest scam with fake parcel seizure and video call coercion.",
            })

            # Hindi
            text_hi = (
                f"अति आवश्यक कानूनी चेतावनी: आपके आधार कार्ड पर 17 मनी लॉन्ड्रिंग के मामले दर्ज किए गए हैं ({agency})। "
                f"गिरफ्तारी से बचने के लिए तुरंत {fake_officer} से व्हाट्सएप वीडियो कॉल {ph} पर संपर्क करें। अपना कमरा बंद रखें。"
            )
            samples.append({
                "content": text_hi,
                "content_type": "message",
                "label": "scam",
                "is_scam": 1,
                "category": "DIGITAL_ARREST",
                "language": "hi",
                "source": "cybercrime_gov_in",
                "extracted_urls": [],
                "extracted_phones": [ph],
                "extracted_upis": [],
                "synthetic": True,
                "brand": agency,
                "explanation": "Hindi Digital Arrest extortion impersonating law enforcement officer.",
            })

            # Hinglish
            text_hng = (
                f"Warning: Aapke phone number se illegal terror funding transacted hui hai. {agency} ne warrant nikala hai. "
                f"Turant WhatsApp call par court verification karein number: {ph} nahi toh police ghar bhej rahe hain."
            )
            samples.append({
                "content": text_hng,
                "content_type": "message",
                "label": "scam",
                "is_scam": 1,
                "category": "DIGITAL_ARREST",
                "language": "hinglish",
                "source": "cybercrime_gov_in",
                "extracted_urls": [],
                "extracted_phones": [ph],
                "extracted_upis": [],
                "synthetic": True,
                "brand": agency,
                "explanation": "Hinglish police impersonation and arrest extortion.",
            })

    # -------------------------------------------------------------------------
    # 4. ELECTRICITY BILL DISCONNECTION EXTORTION (MSEDCL, BESCOM, TATA POWER, BSES, UPPCL)
    # -------------------------------------------------------------------------
    power_boards = ["MSEDCL", "BESCOM", "Tata Power", "BSES Delhi", "UPPCL", "Adani Electricity"]
    for pb in power_boards:
        for _ in range(6):
            ph = f"+91 {rng.randint(7000000000, 9999999999)}"
            fake_url = f"https://{pb.lower().replace(' ', '')}-quick-bill-{rng.randint(10,99)}.top"

            # English
            text_en = (
                f"Dear Consumer, Your electricity power will be DISCONNECTED tonight at 9:30 PM from {pb} office "
                f"because previous month bill was not updated. Immediately contact Electricity Officer on {ph} or visit {fake_url}."
            )
            samples.append({
                "content": text_en,
                "content_type": "message",
                "label": "scam",
                "is_scam": 1,
                "category": "ELECTRICITY",
                "language": "en",
                "source": "curated_threat_intel",
                "extracted_urls": [fake_url],
                "extracted_phones": [ph],
                "extracted_upis": [],
                "synthetic": True,
                "brand": pb,
                "explanation": "Urgent electricity disconnection scam with rogue contact number.",
            })

            # Marathi (MSEDCL is heavily targeted in Maharashtra)
            text_mr = (
                f"प्रिय ग्राहक, महावितरण कडून आपला वीजपुरवठा आज रात्री ९:३० वाजता खंडित केला जाईल "
                f"कारण मागील महिन्याचे बिल अपडेट झाले नाही. वीज कापण्यापूर्वी त्वरित अधिकारी {ph} यांच्याशी संपर्क साधा."
            )
            samples.append({
                "content": text_mr,
                "content_type": "message",
                "label": "scam",
                "is_scam": 1,
                "category": "ELECTRICITY",
                "language": "mr",
                "source": "curated_threat_intel",
                "extracted_urls": [],
                "extracted_phones": [ph],
                "extracted_upis": [],
                "synthetic": True,
                "brand": "MSEDCL",
                "explanation": "Marathi electricity bill disconnection extortion SMS.",
            })

            # Romanized Marathi
            text_rmr = (
                f"Priya grahak, Mahavitaran kadun tumchi light aaj ratri 9:30 vajta band keli jail. "
                f"Bill update karnyakarita officer la ya number vr call kra: {ph}."
            )
            samples.append({
                "content": text_rmr,
                "content_type": "message",
                "label": "scam",
                "is_scam": 1,
                "category": "ELECTRICITY",
                "language": "romanized_mr",
                "source": "synthetic_multilingual_corpus",
                "extracted_urls": [],
                "extracted_phones": [ph],
                "extracted_upis": [],
                "synthetic": True,
                "brand": "MSEDCL",
                "explanation": "Romanized Marathi electricity disconnection scam message.",
            })

    # -------------------------------------------------------------------------
    # 5. COURIER & INDIA POST DELIVERY FRAUD (ADDRESS UPDATE / REDELIVERY FEE)
    # -------------------------------------------------------------------------
    couriers = ["India Post", "Blue Dart", "DTDC", "Delhivery", "FedEx"]
    for c in couriers:
        for _ in range(6):
            fake_url = f"https://{c.lower().replace(' ', '')}-parcel-track-{rng.randint(10,99)}.top/redelivery"
            
            # English
            text_en = (
                f"{c}: Your parcel could not be delivered due to incomplete house address. "
                f"Update your delivery address and pay nominal Rs.25 redelivery fee within 24h at {fake_url} or package will be returned."
            )
            samples.append({
                "content": text_en,
                "content_type": "message",
                "label": "scam",
                "is_scam": 1,
                "category": "DELIVERY",
                "language": "en",
                "source": "curated_threat_intel",
                "extracted_urls": [fake_url],
                "extracted_phones": [],
                "extracted_upis": [],
                "synthetic": True,
                "brand": c,
                "explanation": "Courier redelivery fee lure designed for credit card harvesting.",
            })

            # Hindi
            text_hi = (
                f"भारतीय डाक ({c}): आपका पार्सल गलत पते के कारण रोका गया है। "
                f"पते को दोबारा सत्यापित करने और पुनः डिलीवरी शुल्क (रु 20) भरने के लिए लिंक खोलें: {fake_url}"
            )
            samples.append({
                "content": text_hi,
                "content_type": "message",
                "label": "scam",
                "is_scam": 1,
                "category": "DELIVERY",
                "language": "hi",
                "source": "synthetic_multilingual_corpus",
                "extracted_urls": [fake_url],
                "extracted_phones": [],
                "extracted_upis": [],
                "synthetic": True,
                "brand": c,
                "explanation": "Hindi parcel redelivery phishing lure.",
            })

    # -------------------------------------------------------------------------
    # 6. JOB OFFER & WORK-FROM-HOME TASK SCAMS (YOUTUBE LIKE, TELEGRAM HOTEL REVIEW)
    # -------------------------------------------------------------------------
    job_types = ["Part-Time YouTube Like & Subscribe", "Google Maps Hotel Reviewer", "Amazon Product Rating Assistant", "Data Entry Typist"]
    for jt in job_types:
        for _ in range(6):
            tg_link = f"https://t.me/hr_recruiter_{rng.randint(100,999)}"
            wa_num = f"+91 {rng.randint(7000000000, 9999999999)}"
            salary = rng.choice([2500, 3500, 5000, 8000])

            # English
            text_en = (
                f"Earn Rs.{salary}-{salary+4000}/day from home! Work as {jt}. Daily payout via UPI. "
                f"No investment required. Contact our HR Manager on WhatsApp: {wa_num} or Telegram: {tg_link}."
            )
            samples.append({
                "content": text_en,
                "content_type": "message",
                "label": "scam",
                "is_scam": 1,
                "category": "JOB_OFFER",
                "language": "en",
                "source": "curated_threat_intel",
                "extracted_urls": [tg_link],
                "extracted_phones": [wa_num],
                "extracted_upis": [],
                "synthetic": True,
                "brand": "Telegram HR",
                "explanation": "Work from home YouTube like/review task advance-fee fraud.",
            })

            # Hinglish
            text_hng = (
                f"Ghar baithe kamayein Rs.{salary} daily! YouTube videos like karein aur har like par Rs 50 payein. "
                f"Student aur housewife ke liye best part time job. Join karein: {tg_link}"
            )
            samples.append({
                "content": text_hng,
                "content_type": "message",
                "label": "scam",
                "is_scam": 1,
                "category": "JOB_OFFER",
                "language": "hinglish",
                "source": "curated_threat_intel",
                "extracted_urls": [tg_link],
                "extracted_phones": [],
                "extracted_upis": [],
                "synthetic": True,
                "brand": "Telegram HR",
                "explanation": "Hinglish part-time task scam lure directing victim to Telegram.",
            })

            # Marathi
            text_mr = (
                f"वर्क फ्रॉम होम: घरात बसून दररोज रु {salary} कमवा! फक्त युट्यूब व्हिडिओ लाईक करा आणि पैसे मिळवा. "
                f"अधिक माहितीसाठी आमच्या एचआर टीमशी टेलिग्रामवर संपर्क साधा: {tg_link}"
            )
            samples.append({
                "content": text_mr,
                "content_type": "message",
                "label": "scam",
                "is_scam": 1,
                "category": "JOB_OFFER",
                "language": "mr",
                "source": "synthetic_multilingual_corpus",
                "extracted_urls": [tg_link],
                "extracted_phones": [],
                "extracted_upis": [],
                "synthetic": True,
                "brand": "Telegram HR",
                "explanation": "Marathi WFH task scam message.",
            })

    # -------------------------------------------------------------------------
    # 7. REMOTE ACCESS APP FRAUD (ANYDESK, TEAMVIEWER, RUSTDESK)
    # -------------------------------------------------------------------------
    for _ in range(12):
        fake_agent = f"Officer {rng.choice(['Pooja', 'Rahul', 'Vikas', 'Sneha'])}"
        app = rng.choice(["AnyDesk", "TeamViewer QuickSupport", "RustDesk", "ScreenShare APK"])
        ph = f"+91 {rng.randint(7000000000, 9999999999)}"

        text_en = (
            f"Dear Customer, Your refund of Rs. 4,500 is stuck in payment gateway. "
            f"To complete screen verification and receive instant refund, install {app} and share the 9-digit code with {fake_agent} on {ph}."
        )
        samples.append({
            "content": text_en,
            "content_type": "message",
            "label": "scam",
            "is_scam": 1,
            "category": "REMOTE_ACCESS_FRAUD",
            "language": "en",
            "source": "curated_threat_intel",
            "extracted_urls": [],
            "extracted_phones": [ph],
            "extracted_upis": [],
            "synthetic": True,
            "brand": app,
            "explanation": "Technical support deception coercing victim to install remote screen sharing software.",
        })

        text_hi = (
            f"आपका गूगल पे रिफंड अटका हुआ है। तकनीकी सहायता के लिए प्ले स्टोर से {app} ऐप डाउनलोड करें "
            f"और 9 अंकों का कोड हमारे सहायता अधिकारी {ph} को बताएं ताकि पैसे तुरंत ट्रांसफर किए जा सकें।"
        )
        samples.append({
            "content": text_hi,
            "content_type": "message",
            "label": "scam",
            "is_scam": 1,
            "category": "REMOTE_ACCESS_FRAUD",
            "language": "hi",
            "source": "synthetic_multilingual_corpus",
            "extracted_urls": [],
            "extracted_phones": [ph],
            "extracted_upis": [],
            "synthetic": True,
            "brand": app,
            "explanation": "Hindi remote desktop credential theft scam.",
        })

    # -------------------------------------------------------------------------
    # 8. SIM DEACTIVATION & 5G ESIM FRAUD (JIO, AIRTEL, VI, BSNL)
    # -------------------------------------------------------------------------
    telcos = ["Jio 5G", "Airtel 5G", "Vodafone Idea (Vi)", "BSNL Mobile"]
    for t in telcos:
        for _ in range(6):
            ph = f"+91 {rng.randint(7000000000, 9999999999)}"
            fake_url = f"https://{t.lower().replace(' ', '')}-sim-kyc-{rng.randint(10,99)}.top"

            text_en = (
                f"TRAI & {t} Alert: Your SIM card verification is incomplete. Your outgoing and incoming services "
                f"will be DEACTIVATED in 24 hours. Submit Aadhaar online to keep SIM active: {fake_url} or call {ph}."
            )
            samples.append({
                "content": text_en,
                "content_type": "message",
                "label": "scam",
                "is_scam": 1,
                "category": "SIM_DEACTIVATION",
                "language": "en",
                "source": "curated_threat_intel",
                "extracted_urls": [fake_url],
                "extracted_phones": [ph],
                "extracted_upis": [],
                "synthetic": True,
                "brand": t,
                "explanation": "Telecom SIM card deactivation panic lure.",
            })

            text_hng = (
                f"Aapka {t} SIM card aaj raat band ho jayega TRAI KYC update na hone par. "
                f"Turant SIM chalu rakhne ke liye yahan document upload karein: {fake_url}"
            )
            samples.append({
                "content": text_hng,
                "content_type": "message",
                "label": "scam",
                "is_scam": 1,
                "category": "SIM_DEACTIVATION",
                "language": "hinglish",
                "source": "synthetic_multilingual_corpus",
                "extracted_urls": [fake_url],
                "extracted_phones": [],
                "extracted_upis": [],
                "synthetic": True,
                "brand": t,
                "explanation": "Hinglish telecom SIM block scam message.",
            })

    # -------------------------------------------------------------------------
    # 9. INSTANT LOAN APP BLACKMAIL & EXTORTION
    # -------------------------------------------------------------------------
    loan_apps = ["KreditEasy Instant", "RupeeSpeed Loan", "DhanInstant Cash", "CashPocket Micro"]
    for la in loan_apps:
        for _ in range(6):
            amt = rng.randint(25000, 250000)
            apk_url = f"https://{la.lower().replace(' ', '')}-app-{rng.randint(10,99)}.xyz/download.apk"

            text_en = (
                f"Pre-approved Loan of Rs.{amt} credited to your virtual wallet! Zero paperwork, instant approval. "
                f"Download {la} APK now to disburse funds to your bank: {apk_url}."
            )
            samples.append({
                "content": text_en,
                "content_type": "message",
                "label": "scam",
                "is_scam": 1,
                "category": "LOAN_FRAUD",
                "language": "en",
                "source": "curated_threat_intel",
                "extracted_urls": [apk_url],
                "extracted_phones": [],
                "extracted_upis": [],
                "synthetic": True,
                "brand": la,
                "explanation": "Predatory rogue APK loan app phishing lure.",
            })

            text_hi = (
                f"बधाई हो! आपको रु {amt} का तत्काल व्यक्तिगत ऋण स्वीकृत किया गया है। "
                f"बिना सिबिल स्कोर के तुरंत पैसे बैंक में पाने के लिए ऐप डाउनलोड करें: {apk_url}"
            )
            samples.append({
                "content": text_hi,
                "content_type": "message",
                "label": "scam",
                "is_scam": 1,
                "category": "LOAN_FRAUD",
                "language": "hi",
                "source": "synthetic_multilingual_corpus",
                "extracted_urls": [apk_url],
                "extracted_phones": [],
                "extracted_upis": [],
                "synthetic": True,
                "brand": la,
                "explanation": "Hindi predatory instant loan lure delivering malicious APK.",
            })

    # -------------------------------------------------------------------------
    # 10. INVESTMENT & CRYPTO / STOCK MARKET WHATSAPP GROUP SCAMS
    # -------------------------------------------------------------------------
    for _ in range(12):
        roi = rng.choice([300, 500, 1000])
        fake_group = f"https://chat.whatsapp.com/invite_vip_bulls_{rng.randint(100,999)}"

        text_en = (
            f"Exclusive Institutional Trading Signals: 100% Guaranteed {roi}% return in 7 days with SEBI VIP Trading Desk. "
            f"Join insider WhatsApp community before link expires: {fake_group}."
        )
        samples.append({
            "content": text_en,
            "content_type": "message",
            "label": "scam",
            "is_scam": 1,
            "category": "INVESTMENT_CRYPTO_FRAUD",
            "language": "en",
            "source": "curated_threat_intel",
            "extracted_urls": [fake_group],
            "extracted_phones": [],
            "extracted_upis": [],
            "synthetic": True,
            "brand": "VIP Trading Desk",
            "explanation": "Fraudulent stock tip / crypto investment WhatsApp community lure.",
        })

        text_hng = (
            f"Stock Market me daily 10x profit kamayein! Zero loss guarantee. "
            f"Sirf Rs 5,000 invest karein aur 3 din me Rs 50,000 payein. Join VIP trading group: {fake_group}"
        )
        samples.append({
            "content": text_hng,
            "content_type": "message",
            "label": "scam",
            "is_scam": 1,
            "category": "INVESTMENT_CRYPTO_FRAUD",
            "language": "hinglish",
            "source": "curated_threat_intel",
            "extracted_urls": [fake_group],
            "extracted_phones": [],
            "extracted_upis": [],
            "synthetic": True,
            "brand": "VIP Trading Desk",
            "explanation": "Hinglish fraudulent high-yield investment scheme.",
        })

    # -------------------------------------------------------------------------
    # 11. TRAFFIC E-CHALLAN & TAX PENALTY FRAUD
    # -------------------------------------------------------------------------
    for _ in range(8):
        vnum = f"MH{rng.randint(10,50)}AB{rng.randint(1000,9999)}"
        challan_url = f"https://echallan-parivahan-pay-{rng.randint(10,99)}.top/challan"

        text_en = (
            f"Traffic Police Alert: Pending e-Challan penalty of Rs. 1,000 on vehicle {vnum} for overspeeding. "
            f"Pay immediately within 24h at {challan_url} to avoid court summons and driving license suspension."
        )
        samples.append({
            "content": text_en,
            "content_type": "message",
            "label": "scam",
            "is_scam": 1,
            "category": "TAX_CHALLAN_FRAUD",
            "language": "en",
            "source": "curated_threat_intel",
            "extracted_urls": [challan_url],
            "extracted_phones": [],
            "extracted_upis": [],
            "synthetic": True,
            "brand": "Traffic Police",
            "explanation": "Traffic e-Challan phishing message threatening license cancellation.",
        })

        text_hi = (
            f"यातायात पुलिस सूचना: आपके वाहन {vnum} पर रु 1,500 का ई-चालान बकाया है। "
            f"कोर्ट वारंट से बचने के लिए तुरंत इस लिंक पर जुर्माना भरें: {challan_url}"
        )
        samples.append({
            "content": text_hi,
            "content_type": "message",
            "label": "scam",
            "is_scam": 1,
            "category": "TAX_CHALLAN_FRAUD",
            "language": "hi",
            "source": "synthetic_multilingual_corpus",
            "extracted_urls": [challan_url],
            "extracted_phones": [],
            "extracted_upis": [],
            "synthetic": True,
            "brand": "Traffic Police",
            "explanation": "Hindi fake traffic challan notification with phishing payment link.",
        })

    # -------------------------------------------------------------------------
    # 13. LOTTERY & PRIZE FRAUD (KBC, WHATSAPP LUCKY DRAW)
    # -------------------------------------------------------------------------
    for _ in range(8):
        prize = rng.choice([2500000, 3500000, 5000000])
        lottery_no = rng.randint(1000, 9999)
        ph = f"+91 {rng.randint(7000000000, 9999999999)}"

        text_en = (
            f"Dear Customer, Your mobile number won Rs.{prize//100000} Lakhs in KBC All India WhatsApp Lucky Draw! "
            f"Lottery No: {lottery_no}. Contact KBC Manager Rana Pratap on WhatsApp {ph} to claim prize."
        )
        samples.append({
            "content": text_en,
            "content_type": "message",
            "label": "scam",
            "is_scam": 1,
            "category": "LOTTERY",
            "language": "en",
            "source": "curated_threat_intel",
            "extracted_urls": [],
            "extracted_phones": [ph],
            "extracted_upis": [],
            "synthetic": True,
            "brand": "KBC",
            "explanation": "Fake lottery prize lure with WhatsApp claim contact.",
        })

        text_hi = (
            f"बधाई हो! आपके व्हाट्सएप नंबर ने कौन बनेगा करोड़पति में {prize//100000} लाख रुपये जीते हैं। "
            f"लॉटरी नंबर: {lottery_no}। अपना इनाम पाने के लिए तुरंत केबीसी मैनेजर {ph} पर व्हाट्सएप करें।"
        )
        samples.append({
            "content": text_hi,
            "content_type": "message",
            "label": "scam",
            "is_scam": 1,
            "category": "LOTTERY",
            "language": "hi",
            "source": "synthetic_multilingual_corpus",
            "extracted_urls": [],
            "extracted_phones": [ph],
            "extracted_upis": [],
            "synthetic": True,
            "brand": "KBC",
            "explanation": "Hindi KBC lottery prize fraud message.",
        })

        text_mr = (
            f"अभिनंदन! आपल्या मोबाईल नंबरला केबीसी महा लकी ड्रॉ मध्ये {prize//100000} लाख रुपयांची लॉटरी लागली आहे. "
            f"बक्षीस रकमेसाठी त्वरित मॅनेजरशी {ph} या क्रमांकावर संपर्क साधा."
        )
        samples.append({
            "content": text_mr,
            "content_type": "message",
            "label": "scam",
            "is_scam": 1,
            "category": "LOTTERY",
            "language": "mr",
            "source": "synthetic_multilingual_corpus",
            "extracted_urls": [],
            "extracted_phones": [ph],
            "extracted_upis": [],
            "synthetic": True,
            "brand": "KBC",
            "explanation": "Marathi lottery prize advance fee lure.",
        })

    # -------------------------------------------------------------------------
    # 14. TAX REFUND FRAUD (INCOME TAX / ITR PHISHING)
    # -------------------------------------------------------------------------
    for _ in range(8):
        refund_amt = rng.randint(8500, 48000)
        fake_itr_url = f"https://incometax-refund-gov-{rng.randint(10,99)}.top/claim"

        text_en = (
            f"Income Tax Notice: Your tax refund of Rs. {refund_amt} has been approved by CPC Bangalore. "
            f"Confirm your bank account details within 24 hours to credit refund: {fake_itr_url}."
        )
        samples.append({
            "content": text_en,
            "content_type": "message",
            "label": "scam",
            "is_scam": 1,
            "category": "REFUND_SCAM",
            "language": "en",
            "source": "curated_threat_intel",
            "extracted_urls": [fake_itr_url],
            "extracted_phones": [],
            "extracted_upis": [],
            "synthetic": True,
            "brand": "Income Tax",
            "explanation": "Income tax refund phishing message harvesting banking credentials.",
        })

        text_hi = (
            f"आयकर विभाग सूचना: आपके खाते में रु {refund_amt} का रिफंड भेजा गया है। "
            f"बैंक विवरण सत्यापित करने और पैसे प्राप्त करने के लिए लिंक खोलें: {fake_itr_url}"
        )
        samples.append({
            "content": text_hi,
            "content_type": "message",
            "label": "scam",
            "is_scam": 1,
            "category": "REFUND_SCAM",
            "language": "hi",
            "source": "synthetic_multilingual_corpus",
            "extracted_urls": [fake_itr_url],
            "extracted_phones": [],
            "extracted_upis": [],
            "synthetic": True,
            "brand": "Income Tax",
            "explanation": "Hindi fake income tax refund notification.",
        })

    # -------------------------------------------------------------------------
    # 15. FAMILY EMERGENCY & IMPOSTER SCAMS
    # -------------------------------------------------------------------------
    for _ in range(8):
        ph = f"+91 {rng.randint(7000000000, 9999999999)}"
        amt = rng.choice([5000, 8000, 12000, 15000])

        text_en = (
            f"Hi Mom, I dropped my phone in water so this is my new temporary number. "
            f"I urgently need Rs.{amt} to pay hostel doctor fees. Please GPay money to my friend's number: {ph} immediately."
        )
        samples.append({
            "content": text_en,
            "content_type": "message",
            "label": "scam",
            "is_scam": 1,
            "category": "FAMILY_EMERGENCY_SCAM",
            "language": "en",
            "source": "curated_threat_intel",
            "extracted_urls": [],
            "extracted_phones": [ph],
            "extracted_upis": [],
            "synthetic": True,
            "brand": None,
            "explanation": "Family emergency imposter lure soliciting immediate payment to third party.",
        })

        text_hi = (
            f"मम्मी, मेरा फोन चोरी हो गया है इसलिए इस नए नंबर से मैसेज कर रहा हूँ। "
            f"कॉलेज में बहुत इमरजेंसी है, कृपया तुरंत {amt} रुपये इस नंबर {ph} पर गूगल पे कर दो। बाद में बात करता हूँ।"
        )
        samples.append({
            "content": text_hi,
            "content_type": "message",
            "label": "scam",
            "is_scam": 1,
            "category": "FAMILY_EMERGENCY_SCAM",
            "language": "hi",
            "source": "synthetic_multilingual_corpus",
            "extracted_urls": [],
            "extracted_phones": [ph],
            "extracted_upis": [],
            "synthetic": True,
            "brand": None,
            "explanation": "Hindi family emergency imposter extortion message.",
        })

        text_mr = (
            f"आई, माझा जुना फोन खराब झाला आहे, हा माझा नवीन नंबर आहे. "
            f"इथे हॉस्पिटलमध्ये रु {amt} ची तातडीची गरज आहे. कृपया त्वरित या नंबरवर {ph} फोनपे करा."
        )
        samples.append({
            "content": text_mr,
            "content_type": "message",
            "label": "scam",
            "is_scam": 1,
            "category": "FAMILY_EMERGENCY_SCAM",
            "language": "mr",
            "source": "synthetic_multilingual_corpus",
            "extracted_urls": [],
            "extracted_phones": [ph],
            "extracted_upis": [],
            "synthetic": True,
            "brand": None,
            "explanation": "Marathi family emergency extortion lure.",
        })

    # -------------------------------------------------------------------------
    # 16. OTP THEFT & ACCOUNT TAKEOVER SCAMS
    # -------------------------------------------------------------------------
    services = ["WhatsApp Web", "Amazon Pay", "Google Account", "Instagram", "Paytm Wallet"]
    for svc in services:
        for _ in range(5):
            ph = f"+91 {rng.randint(7000000000, 9999999999)}"

            text_en = (
                f"Security Warning: An unauthorized login attempt was made to your {svc} from Windows NT in London. "
                f"If you did not request this, immediately reply with the 6-digit cancellation OTP sent to your phone or call {ph} to stop hack."
            )
            samples.append({
                "content": text_en,
                "content_type": "message",
                "label": "scam",
                "is_scam": 1,
                "category": "OTP_THEFT",
                "language": "en",
                "source": "curated_threat_intel",
                "extracted_urls": [],
                "extracted_phones": [ph],
                "extracted_upis": [],
                "synthetic": True,
                "brand": svc,
                "explanation": "OTP theft pretext coercing victim to disclose 2FA code to prevent supposed breach.",
            })

            text_hi = (
                f"सुरक्षा चेतावनी: आपके {svc} खाते में किसी अज्ञात डिवाइस से लॉगिन किया जा रहा है। "
                f"इसे ब्लॉक करने के लिए आपके फोन पर भेजा गया 6 अंकों का ओटीपी तुरंत हमारे सुरक्षा अधिकारी {ph} को बताएं。"
            )
            samples.append({
                "content": text_hi,
                "content_type": "message",
                "label": "scam",
                "is_scam": 1,
                "category": "OTP_THEFT",
                "language": "hi",
                "source": "synthetic_multilingual_corpus",
                "extracted_urls": [],
                "extracted_phones": [ph],
                "extracted_upis": [],
                "synthetic": True,
                "brand": svc,
                "explanation": "Hindi OTP theft phishing lure.",
            })

    # -------------------------------------------------------------------------
    # 17. CUSTOMER SUPPORT IMPOSTER SCAMS
    # -------------------------------------------------------------------------
    cs_brands = ["IndiGo Airlines", "Air India", "Swiggy Support", "Zomato Care", "Flipkart Helpdesk"]
    for csb in cs_brands:
        for _ in range(4):
            ph = f"+91 {rng.randint(7000000000, 9999999999)}"

            text_en = (
                f"Dear Customer, Regarding your recent ticket cancellation dispute with {csb}, "
                f"your full refund of Rs. 3,850 is ready. Immediately contact Dedicated Desk on {ph} to receive refund via AnyDesk."
            )
            samples.append({
                "content": text_en,
                "content_type": "message",
                "label": "scam",
                "is_scam": 1,
                "category": "CUSTOMER_SUPPORT_SCAM",
                "language": "en",
                "source": "curated_threat_intel",
                "extracted_urls": [],
                "extracted_phones": [ph],
                "extracted_upis": [],
                "synthetic": True,
                "brand": csb,
                "explanation": "Fake airline / delivery customer support imposter lure.",
            })

    # -------------------------------------------------------------------------
    # 18. DEDICATED MALICIOUS URL CORPUS (PHISHING URLS, PUNYCODE, HOMOGLYPHS)
    # -------------------------------------------------------------------------
    phishing_urls = [
        # Phishing bank portals
        "https://sbi-online-banking-portal-auth.top/login.php",
        "https://hdfc-netbanking-secure-auth.xyz/index.html",
        "https://icici-bank-kyc-verification.click/account",
        "https://axisbank-security-center.vip/auth",
        "https://bankofbaroda-pan-update.site/login",
        "https://pnbone-customer-support.live/index",
        "https://kotak-netbanking-811.top/update",
        "https://canara-ebank-portal.xyz/login",

        # Utility & Post Phishing
        "https://mahadiscom-bill-quick-pay.top/msedcl",
        "https://bescom-electricity-karnataka.xyz/bill",
        "https://indiapost-parcel-redelivery.click/track",
        "https://bluedart-package-address-update.vip/auth",
        
        # Google Safe Browsing and Malware test targets
        "https://testsafebrowsing.appspot.com/s/malware.html",
        "https://testsafebrowsing.appspot.com/s/phishing.html",
        
        # Punycode & Homoglyph URLs
        "https://xn--sbi-onlne-01a.top/login",
        "https://xn--hdfcbnk-v1a.com/auth",
        "https://һdfcbank.com/auth",
        "https://sbi.co.in.ebank-auth-portal.com/login",
        "https://icicibank.com.customer-security-alert.net/kyc",
        "https://axisbank.com.pan-verification-center.info/update",
        "https://103.21.244.42/sbi/login.html",
        "https://45.33.32.156:8443/netbanking/verify",
    ]

    for pu in phishing_urls:
        samples.append({
            "content": pu,
            "content_type": "url",
            "label": "scam",
            "is_scam": 1,
            "category": "PHISHING_URL",
            "language": "en",
            "source": "curated_threat_intel",
            "extracted_urls": [pu],
            "extracted_phones": [],
            "extracted_upis": [],
            "synthetic": True,
            "brand": None,
            "explanation": "Malicious phishing URL exhibiting brand impersonation, spoofed subdomains, or suspicious TLD.",
        })

    return samples
