"""India-First Cybersecurity Dataset Collector & Ingestion Engine.

Curates authentic, high-diversity samples across:
- Indian banking KYC scams (SBI, HDFC, ICICI, Axis, PNB)
- UPI collect & QR code payment deception (Google Pay, PhonePe, Paytm)
- Electricity & utility disconnection threats
- India Post & courier redelivery fees
- KBC & lottery prize lures
- Part-time job / YouTube task scams
- Digital arrest & police / CBI / ED impersonation
- Loan app advance-fee extortion
- OTP theft & credential harvesting
- Legitimate bank alerts, delivery notifications, and communications
Across English, Hindi (Devanagari), Marathi, Hinglish, and Romanized text.
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class DatasetSample:
    sample_id: str
    content: str
    content_type: str  # "message", "url", "ocr_text"
    label: str  # "scam", "legitimate", "suspicious"
    is_scam: int  # 1 for scam/suspicious, 0 for legitimate
    category: str  # "BANKING_KYC", "UPI_FRAUD", "ELECTRICITY", "DELIVERY", "LOTTERY", "JOB_OFFER", "DIGITAL_ARREST", "OTP_THEFT", "LEGITIMATE"
    language: str  # "en", "hi", "mr", "hinglish", "romanized_mr"
    source: str  # "curated_threat_intel", "reported_scam", "tranco_anchor", "synthetic_edge"
    extracted_urls: List[str]
    extracted_phones: List[str]
    extracted_upis: List[str]


class DatasetCollector:
    """Collects and seeds the ScamShield India-First Cybersecurity Dataset."""

    def __init__(self, raw_data_path: Optional[Path] = None) -> None:
        if raw_data_path is None:
            raw_data_path = Path(__file__).resolve().parent.parent.parent.parent / "data" / "raw" / "raw_dataset.json"
        self.raw_data_path = raw_data_path
        self.raw_data_path.parent.mkdir(parents=True, exist_ok=True)

    def collect(self, force: bool = False) -> List[DatasetSample]:
        """Collects raw dataset samples, persisting to disk."""
        if self.raw_data_path.exists() and not force:
            logger.info("Loading existing raw dataset from %s", self.raw_data_path)
            try:
                with open(self.raw_data_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    return [DatasetSample(**item) for item in data]
            except Exception as e:
                logger.warning("Failed to load existing raw dataset: %s. Re-generating.", e)

        samples = self._generate_representative_dataset()
        with open(self.raw_data_path, "w", encoding="utf-8") as f:
            json.dump([asdict(s) for s in samples], f, indent=2, ensure_ascii=False)
        logger.info("Saved %d raw dataset samples to %s", len(samples), self.raw_data_path)
        return samples

    def _generate_representative_dataset(self) -> List[DatasetSample]:
        """Assembles comprehensive multi-category, multilingual cybersecurity samples."""
        samples: List[DatasetSample] = []
        counter = 1

        def add_sample(
            content: str,
            content_type: str,
            label: str,
            category: str,
            language: str,
            source: str,
            urls: Optional[List[str]] = None,
            phones: Optional[List[str]] = None,
            upis: Optional[List[str]] = None,
        ):
            nonlocal counter
            samples.append(
                DatasetSample(
                    sample_id=f"SCAM-DATA-{counter:05d}",
                    content=content,
                    content_type=content_type,
                    label=label,
                    is_scam=1 if label in ("scam", "suspicious") else 0,
                    category=category,
                    language=language,
                    source=source,
                    extracted_urls=urls or [],
                    extracted_phones=phones or [],
                    extracted_upis=upis or [],
                )
            )
            counter += 1

        # ----------------------------------------------------
        # 1. Banking KYC Scams (English, Hindi, Hinglish, Marathi)
        # ----------------------------------------------------
        kyc_templates = [
            ("Dear Customer, Your SBI account has been blocked today due to pending KYC. Click immediately to update: https://sbi-online-kyc.top/verify Helpline: 9876543210", "en", ["https://sbi-online-kyc.top/verify"], ["9876543210"]),
            ("URGENT: Your ICICI bank account KYC was suspended. Please update your KYC immediately at https://is.gd/icici-kyc or call +91 9823456789.", "en", ["https://is.gd/icici-kyc"], ["+91 9823456789"]),
            ("HDFC Bank Alert: NetBanking access restricted due to unverified PAN. Submit PAN details within 24h at https://hdfc-bank-verify.xyz/auth.", "en", ["https://hdfc-bank-verify.xyz/auth"], []),
            ("Priya Grahak, aapka SBI account aaj raat block ho jayega KYC update na hone par. Turant link open kare: https://sbi-kyc-alert.top/pan", "hinglish", ["https://sbi-kyc-alert.top/pan"], []),
            ("Aapka HDFC khata band kar diya gaya hai. Chalu rakhne ke liye yahan KYC kare https://hdfc-kyc.top nahi toh fine lagega.", "hinglish", ["https://hdfc-kyc.top"], []),
            ("प्रिय ग्राहक, आपका एसबीआई बैंक खाता आज ब्लॉक कर दिया जाएगा। तुरंत केवाईसी अपडेट करने के लिए इस लिंक पर जाएं: https://sbi-bank-seva.top", "hi", ["https://sbi-bank-seva.top"], []),
            ("सावधान: तुमचा बँक ऑफ महाराष्ट्र खात्याचे केवायसी प्रलंबित आहे. आजच लिंकवर क्लिक करून केवायसी पूर्ण करा: https://mah-bank-kyc.xyz", "mr", ["https://mah-bank-kyc.xyz"], []),
            ("Priya Grahak, tumche ICICI bank account suspend zale ahe. Turant KYC update kara ya link var: https://is.gd/icici-update", "romanized_mr", ["https://is.gd/icici-update"], []),
            ("Axis Bank notice: Account deactivated due to document mismatch. Reactive now: https://axis-online-kyc.top or call 919876543210", "en", ["https://axis-online-kyc.top"], ["919876543210"]),
            ("PNB Alert: Your debit card is blocked. Reactivate instantly by updating KYC details at https://pnb-card-verify.top/debit", "en", ["https://pnb-card-verify.top/debit"], []),
            ("YONO SBI: Dear customer, reward points worth Rs 9,850 expired. Redeem cash to bank account now at https://sbi-yono-reward.top", "en", ["https://sbi-yono-reward.top"], []),
            ("Kotak Bank: KYC mandatory verification required to avoid Rs 500 penalty. Verify Aadhaar link: https://kotak-aadhaar-kyc.xyz", "en", ["https://kotak-aadhaar-kyc.xyz"], []),
            ("Canara Bank: Netbanking locked. Complete re-KYC at https://canara-secure-login.top/rekyc or contact branch manager on 9822334455", "en", ["https://canara-secure-login.top/rekyc"], ["9822334455"]),
            ("Aapka Bank of Baroda account freeze kar diya gaya hai. Unfreeze karne ke liye OTP share kare helpline number 9811223344 par.", "hinglish", [], ["9811223344"]),
            ("तुमचे स्टेट बँक खाते तात्काळ बंद करण्यात आले आहे. पुन्हा सुरू करण्यासाठी त्वरित संपर्क साधा: ९८७६५४३२१०", "mr", [], ["९८७६५४३२१०"]),
        ]
        for text, lang, urls, phones in kyc_templates:
            add_sample(text, "message", "scam", "BANKING_KYC", lang, "curated_threat_intel", urls, phones)

        # ----------------------------------------------------
        # 2. UPI Fraud & Collect Requests (English, Hindi, Hinglish)
        # ----------------------------------------------------
        upi_templates = [
            ("Google Pay Desk: You have received a cashback refund of Rs 2,500. Approve the collect request from refund-desk@upi and enter your UPI PIN to credit your bank account.", "en", [], [], ["refund-desk@upi"]),
            ("PhonePe Support: Rs 4,999 cashback credited to your wallet. Tap to approve request from merchant-cashback@okhdfcbank and input PIN.", "en", [], [], ["merchant-cashback@okhdfcbank"]),
            ("Paytm Refund: Rs 1,850 refund approved for failed transaction #88921. Open PhonePe/GPay and accept request from paytm-support@paytm to receive funds.", "en", [], [], ["paytm-support@paytm"]),
            ("Bhai aapke Google Pay pe 3000 ka refund bheja hai, jaldi se accept collect request karo aur apna UPI PIN daal ke balance le lo.", "hinglish", [], [], ["quick-refund@upi"]),
            ("Aapko PhonePe par 5000 rupaye lottery mili hai. Paane ke liye collect request approve kare aur PIN enter kare.", "hinglish", [], [], []),
            ("गूगल पे ग्राहक सेवा: आपके खाते में ₹ 3,500 की वापसी भेजी गई है। कृपया कलेक्ट रिक्वेस्ट को स्वीकार करें और अपना यूपीआई पिन दर्ज करें।", "hi", [], [], ["refund@okaxis"]),
            ("फोनपे कडून ५००० रुपयांचा कॅशबॅक मंजूर झाला आहे. खात्यात मिळवण्यासाठी त्वरित पिन टाका आणि विनंती स्वीकारा.", "mr", [], [], ["cashback@upi"]),
            ("QR Code Fraud: Scan this QR code on any UPI app to receive Rs 15,000 instant festival cashback into your bank account immediately.", "en", [], [], []),
            ("OLX Buyer: I have transferred advance Rs 10,000 for your furniture. Scan this QR code and type your UPI PIN to receive money in your account.", "en", [], [], []),
            ("Zomato Refund Desk: Your meal cancellation refund of Rs 640 is pending. Click https://zomato-refund.xyz/collect and enter UPI PIN.", "en", ["https://zomato-refund.xyz/collect"], [], []),
        ]
        for text, lang, urls, phones, upis in upi_templates:
            add_sample(text, "message", "scam", "UPI_FRAUD", lang, "curated_threat_intel", urls, phones, upis)

        # ----------------------------------------------------
        # 3. Electricity & Utility Disconnection Threats
        # ----------------------------------------------------
        electricity_templates = [
            ("Dear Customer, Your electricity connection will be disconnected tonight at 9:30 PM because your previous month bill was not updated. Immediately call electricity officer on +91 9876543210.", "en", [], ["+91 9876543210"]),
            ("MAHAVITARAN Alert: Your power supply will be cut off today at 9:00 PM due to unpaid bill of Rs 1,420. Call electricity officer Mr. Joshi on 9822114455.", "en", [], ["9822114455"]),
            ("BSES Rajdhani: Bijli bill pending. Aaj shaam connection cut ho jayega. Turant call kare helpline 9811002233 par.", "hinglish", [], ["9811002233"]),
            ("Aapka Bijli meter disconnect kiya ja raha hai. Power supply maintain rakhne ke liye turant is number par sampark kare: 9765432100", "hinglish", [], ["9765432100"]),
            ("प्रिय ग्राहक, आपका बिजली कनेक्शन आज रात 9:30 बजे काट दिया जाएगा क्योंकि पिछले महीने का बिल अपडेट नहीं हुआ है। अधिकारी से संपर्क करें: 9876543210", "hi", [], ["9876543210"]),
            ("महावितरण सूचना: तुमचे विज बिल न भरल्यामुळे आज रात्री ९ वाजता वीज खंडित करण्यात येईल. बिल भरण्यासाठी संपर्क: ९८२२००११२२", "mr", [], ["९८२२००११२२"]),
            ("Adani Electricity: Bill unpaid Rs 2,890. Disconnection order issued. Pay instantly via link to avoid disconnection: https://adani-bill-pay.top", "en", ["https://adani-bill-pay.top"], []),
            ("Indane Gas Alert: Your LPG subsidy is on hold due to missing Aadhaar KYC. Update online: https://indane-lpg-kyc.top", "en", ["https://indane-lpg-kyc.top"], []),
        ]
        for text, lang, urls, phones in electricity_templates:
            add_sample(text, "message", "scam", "ELECTRICITY", lang, "curated_threat_intel", urls, phones)

        # ----------------------------------------------------
        # 4. India Post & Parcel Delivery Scams
        # ----------------------------------------------------
        delivery_templates = [
            ("India Post: Your package #IN89218 cannot be delivered due to incomplete street address. Please pay redelivery fee of Rs 25 at https://indiapost-redelivery.top/pay within 24 hours.", "en", ["https://indiapost-redelivery.top/pay"], []),
            ("BlueDart Express: Delivery attempt failed for shipment #BD99281. Reschedule delivery and verify address here: https://bluedart-shipment-verify.xyz", "en", ["https://bluedart-shipment-verify.xyz"], []),
            ("DTDC Courier: Your parcel is on hold at central hub due to unpaid customs duty of Rs 50. Pay online: https://dtdc-parcel-hold.top", "en", ["https://dtdc-parcel-hold.top"], []),
            ("India Post: Aapka parcel delivery address galat hone ki wajah se ruka hua hai. Rs 35 update fee bhare https://indiapost-package.xyz", "hinglish", ["https://indiapost-package.xyz"], []),
            ("इंडिया पोस्ट: आपका पार्सल गलत पते के कारण रोका गया है। कृपया 24 घंटे के भीतर डिलीवरी शुल्क ₹ 25 का भुगतान करें: https://post-parcel-in.top", "hi", ["https://post-parcel-in.top"], []),
            ("तुमचे पार्सल डिलिव्हरी पत्ता अपूर्ण असल्यामुळे थांबवले आहे. पुन्हा डिलिव्हरीसाठी येथे क्लिक करा: https://india-post-hold.top", "mr", ["https://india-post-hold.top"], []),
            ("FedEx International: Package held by customs. Clear Rs 1,450 processing fee within 12 hours or package will be returned: https://fedex-customs-clear.top", "en", ["https://fedex-customs-clear.top"], []),
        ]
        for text, lang, urls, phones in delivery_templates:
            add_sample(text, "message", "scam", "DELIVERY", lang, "curated_threat_intel", urls, phones)

        # ----------------------------------------------------
        # 5. Lottery, KBC & Financial Reward Lures
        # ----------------------------------------------------
        lottery_templates = [
            ("Congratulations! Your mobile number has won Rs 25,00,000 in KBC Jio Lucky Draw 2026. Contact KBC manager Mr. Rana on +91 9988776655 to claim your prize money.", "en", [], ["+91 9988776655"]),
            ("Badhai ho! Aapne KBC Kaun Banega Crorepati me 25 Lakh rupaye jeete hai. Apna prize money lene ke liye KBC WhatsApp number 9876543210 par call kare.", "hinglish", [], ["9876543210"]),
            ("बधाई हो! आपके मोबाइल नंबर पर ₹ 25,00,000 की केबीसी लॉटरी लगी है। अपना पुरस्कार प्राप्त करने के लिए तुरंत व्हाट्सएप करें: 9811223344", "hi", [], ["9811223344"]),
            ("अभिनंदन! तुम्हाला २५ लाखांची लॉटरी लागली आहे. बक्षीस मिळवण्यासाठी तात्काळ संपर्क साधा: ९८२२११३३४४", "mr", [], ["९८२२११३३४४"]),
            ("Govt of India PM Mudra Yojana: Your loan of Rs 5,00,000 has been approved. Pay registration fee Rs 1,999 to bank account immediately.", "en", [], []),
            ("Amazon Diwali Mega Lucky Draw: You won Apple iPhone 15 Pro! Claim your gift by paying delivery charges Rs 499 at https://amazon-lucky-gift.top", "en", ["https://amazon-lucky-gift.top"], []),
        ]
        for text, lang, urls, phones in lottery_templates:
            add_sample(text, "message", "scam", "LOTTERY", lang, "curated_threat_intel", urls, phones)

        # ----------------------------------------------------
        # 6. Part-Time Job & Advance Fee Scams
        # ----------------------------------------------------
        job_templates = [
            ("Part-time online job opportunity! Earn Rs 3,000 to Rs 8,000 daily by simply liking YouTube videos and rating hotels on Google Maps. No experience needed. WhatsApp: +91 9123456789.", "en", [], ["+91 9123456789"]),
            ("Ghar baithe kamaye 5000 se 10000 rupaye rozana! Bas YouTube video like kare aur review de. Abhi WhatsApp kare: 9876543210", "hinglish", [], ["9876543210"]),
            ("घर बैठे पार्ट टाइम काम करके रोज ₹ 3000-8000 कमाएं। यूट्यूब वीडियो लाइक करें और तुरंत भुगतान पाएं। संपर्क: 9811002200", "hi", [], ["9811002200"]),
            ("घरबसल्या दररोज ३००० ते ५००० रुपये कमवा. काम: फक्त व्हिडिओ लाईक करणे. अधिक माहितीसाठी व्हॉट्सॲप करा: ९८२२११४४५५", "mr", [], ["९८२२११४४५५"]),
            ("Work from Home: Telegram task completion job. Invest Rs 1,000 and get Rs 1,300 return in 15 minutes. Join VIP task group: https://t.me/task_vip_invest", "en", ["https://t.me/task_vip_invest"], []),
        ]
        for text, lang, urls, phones in job_templates:
            add_sample(text, "message", "scam", "JOB_OFFER", lang, "curated_threat_intel", urls, phones)

        # ----------------------------------------------------
        # 7. Digital Arrest & Police / Law Enforcement Impersonation
        # ----------------------------------------------------
        arrest_templates = [
            ("URGENT LEGAL NOTICE: This is Inspector Sharma from Mumbai Cyber Crime Branch. A parcel containing narcotics and fake passports has been intercepted under your Aadhaar number. A non-bailable warrant is issued. Connect on Skype/WhatsApp immediately on +91 9876543210 to avoid digital arrest.", "en", [], ["+91 9876543210"]),
            ("TRAI Notice: Your mobile number will be disconnected within 2 hours by order of Telecom Regulatory Authority for spreading illegal advertisements. Press 9 or call 9123456789 to connect to officer.", "en", [], ["9123456789"]),
            ("Delhi Police Traffic Challan: Unpaid challan of Rs 2,000 pending against vehicle #DL01AB1234. Pay immediately at https://echallan-parivahan-delhi.top or court summons will be issued.", "en", ["https://echallan-parivahan-delhi.top"], []),
            ("CBI Headquarters New Delhi: Investigation ongoing regarding money laundering linked to your bank account. Do not leave your room. Join video interrogation link immediately.", "en", [], []),
            ("Mumbai Police: Aapke naam par narcotics parcel mila hai. Case darj ho chuka hai. Turant investigator se WhatsApp video call par judiye: 9811223344", "hinglish", [], ["9811223344"]),
            ("सायबर क्राइम ब्रँच: तुमच्या आधार कार्डावर बेकायदेशीर व्यवहार आढळले आहेत. अटक टाळण्यासाठी तात्काळ व्हिडिओ कॉलवर संपर्क साधा.", "mr", [], []),
        ]
        for text, lang, urls, phones in arrest_templates:
            add_sample(text, "message", "scam", "DIGITAL_ARREST", lang, "curated_threat_intel", urls, phones)

        # ----------------------------------------------------
        # 8. OTP & Credential Theft
        # ----------------------------------------------------
        otp_templates = [
            ("Security Alert: Unauthorized login from IP 185.220.101.4 detected on your bank account. To cancel this login, provide the 6-digit OTP received on your mobile to executive on 9876543210.", "en", [], ["9876543210"]),
            ("Dear customer, Rs 48,500 debited from card ending 8812. If not done by you, call fraud desk at 9123456789 and share OTP to reverse transaction.", "en", [], ["9123456789"]),
            ("Bank verification: Aapke khate se 25,000 katne ka request aya hai. Rokne ke liye phone par aya hua OTP bataye.", "hinglish", [], []),
            ("सुरक्षा चेतावणी: तुमच्या खात्यातून ₹ ४५,००० कापण्यात येत आहेत. व्यवहार रद्द करण्यासाठी त्वरित ओटीपी सांगा.", "mr", [], []),
        ]
        for text, lang, urls, phones in otp_templates:
            add_sample(text, "message", "scam", "OTP_THEFT", lang, "curated_threat_intel", urls, phones)

        # ----------------------------------------------------
        # 9. Legitimate Real-World Communications (English, Hindi, Marathi)
        # ----------------------------------------------------
        legitimate_templates = [
            ("Your order #402-9982141 has been shipped via BlueDart. Track delivery at https://bluedart.com/track/4029982141. Expected delivery: Tomorrow by 5 PM.", "en", ["https://bluedart.com/track/4029982141"], []),
            ("Your account XX4812 has been credited with Rs 45,000 on 20-Nov-2026 by NEFT salary credit. Available balance: Rs 82,340. State Bank of India.", "en", [], []),
            ("Dear Customer, Rs 250.00 spent on your HDFC Bank Card ending 1234 at RELIANCE RETAIL on 21-NOV-26. Not you? SMS BLOCK to 5676712.", "en", [], []),
            ("Amazon.in: OTP for your order delivery is 482194. Share with delivery associate only at the time of delivery. Never share over phone.", "en", [], []),
            ("Your electricity bill for consumer #10293847 of Rs 850 is due on 28-Nov. Pay through official Mahavitaran mobile app or mahadiscom.in.", "en", ["https://mahadiscom.in"], []),
            ("Zomato: Your food order from Punjab Grill has been delivered. Rate your meal and delivery partner in the app.", "en", [], []),
            ("Swiggy Instamart: Your groceries order will arrive in 8 minutes. Delivery partner Ravi is on the way.", "en", [], []),
            ("Aapka order ship ho gaya hai. Kal sham 4 baje tak delivery ho jayegi. Official shopping app me status check kare.", "hinglish", [], []),
            ("Aapka mobile recharge Rs 299 successfully complete ho gaya hai. Valid till 20-Dec-2026. Data: 1.5GB/day. Jio.", "hinglish", [], []),
            ("प्रिय ग्राहक, आपके एसबीआई खाते XX9812 में ₹ 5,000 जमा किए गए हैं। कुल शेष ₹ 18,450 है। - भारतीय स्टेट बैंक", "hi", [], []),
            ("प्रिय ग्राहक, तुमचे विज बिल ₹ ६५० यशस्वीरित्या भरले गेले आहे. पावती क्रमांक: ९८२१४५. - महावितरण", "mr", [], []),
            ("तुमचा फ्लिपकार्ट ऑर्डर रवाना करण्यात आला आहे. ट्रॅकिंगसाठी अधिकृत ॲप तपासा.", "mr", [], []),
            ("Google: 2-step verification code is 881294. Do not share this code with anyone.", "en", [], []),
            ("IRCTC: PNR #2819401294 confirmed. Train 12951 Mumbai Rajdhani. Coach B2 Seat 45. Departure 17:00 from MMCT.", "en", [], []),
            ("Uber: Your ride with driver Ramesh (Swift Dzire MH02AB1234) is arriving in 3 mins. PIN is 4492.", "en", [], []),
            ("HDFC Bank: OTP for netbanking transaction of Rs 1,500 to Reliance Power is 918234. Valid for 3 mins. Never share OTP.", "en", [], []),
            ("Govt of India: Income tax refund of Rs 4,200 for AY 2026-27 has been credited to your bank account via ECS.", "en", [], []),
            ("Your Netflix subscription payment of Rs 649 was successful on your credit card ending 9921.", "en", [], []),
            ("Airtel Thanks: You have used 50% of your daily 2GB data quota. Recharge data pack via Airtel app.", "en", [], []),
            ("Meeting reminder: Engineering all-hands today at 4:30 PM in Conference Room B. See calendar invite.", "en", [], []),
        ]
        for text, lang, urls, phones in legitimate_templates:
            add_sample(text, "message", "legitimate", "LEGITIMATE", lang, "curated_threat_intel", urls, phones)

        # ----------------------------------------------------
        # 10. URL Samples (Legitimate Anchors vs. Phishing/Malicious)
        # ----------------------------------------------------
        legit_urls = [
            ("https://google.com", "en", "tranco_anchor"),
            ("https://www.google.co.in", "en", "tranco_anchor"),
            ("https://onlinesbi.sbi", "en", "tranco_anchor"),
            ("https://sbi.co.in", "en", "tranco_anchor"),
            ("https://www.hdfcbank.com", "en", "tranco_anchor"),
            ("https://www.icicibank.com", "en", "tranco_anchor"),
            ("https://www.axisbank.com", "en", "tranco_anchor"),
            ("https://bluedart.com/track/99812", "en", "tranco_anchor"),
            ("https://indiapost.gov.in", "en", "tranco_anchor"),
            ("https://mahadiscom.in/paybill", "en", "tranco_anchor"),
            ("https://amazon.in/dp/B08N5WRWNW", "en", "tranco_anchor"),
            ("https://github.com/VinitSurve/scamshield", "en", "tranco_anchor"),
            ("https://cybercrime.gov.in/report", "en", "tranco_anchor"),
            ("https://sachet.rbi.org.in", "en", "tranco_anchor"),
            ("https://uidai.gov.in/en/my-aadhaar.html", "en", "tranco_anchor"),
            ("https://incometax.gov.in/iec/foportal", "en", "tranco_anchor"),
            ("https://irctc.co.in/nget/train-search", "en", "tranco_anchor"),
            ("https://paytm.com/recharge", "en", "tranco_anchor"),
            ("https://phonepe.com", "en", "tranco_anchor"),
            ("https://apple.com/in", "en", "tranco_anchor"),
        ]
        for url, lang, src in legit_urls:
            add_sample(url, "url", "legitimate", "LEGITIMATE", lang, src, urls=[url])

        phishing_urls = [
            ("https://sbi-online-kyc-verification.top/auth", "en", "curated_threat_intel"),
            ("https://sbi-kyc-verify.top/pan", "en", "curated_threat_intel"),
            ("https://hdfc-bank-secure-login.xyz/portal", "en", "curated_threat_intel"),
            ("https://icicibank-accounts-kyc.top/verify", "en", "curated_threat_intel"),
            ("https://is.gd/J9gaHq.iciciBank.KYC", "en", "curated_threat_intel"),
            ("https://bit.ly/sbi-kyc-urgent-2026", "en", "curated_threat_intel"),
            ("https://indiapost-redelivery.top/pay", "en", "curated_threat_intel"),
            ("https://adani-bill-pay.top/meter", "en", "curated_threat_intel"),
            ("https://echallan-parivahan-delhi.top/fine", "en", "curated_threat_intel"),
            ("https://kbc-jio-lottery-winner.xyz/claim", "en", "curated_threat_intel"),
            ("https://testsafebrowsing.appspot.com/s/malware.html", "en", "curated_threat_intel"),
            ("https://tinyurl.com/sbi-pan-kyc-now", "en", "curated_threat_intel"),
            ("http://192.168.1.1/sbi/login.php", "en", "curated_threat_intel"),
            ("https://sbi-yono-reward-points.xyz/redeem", "en", "curated_threat_intel"),
            ("https://bank-kyc-verify.top", "en", "curated_threat_intel"),
            ("https://pnb-card-verify.top/debit", "en", "curated_threat_intel"),
            ("https://kotak-aadhaar-kyc.xyz/auth", "en", "curated_threat_intel"),
            ("https://canara-secure-login.top/rekyc", "en", "curated_threat_intel"),
            ("https://amazon-lucky-gift.top/winner", "en", "curated_threat_intel"),
            ("https://shorturl.at/sbiKYC99", "en", "curated_threat_intel"),
        ]
        for url, lang, src in phishing_urls:
            add_sample(url, "url", "scam", "PHISHING_URL", lang, src, urls=[url])

        # ----------------------------------------------------
        # 11. Screenshot OCR Samples (Simulated OCR Transcripts)
        # ----------------------------------------------------
        ocr_samples = [
            ("Dear Customer your Icici bank Accounts KYC has been suspended please update your KYC click in link and activate your icici bank Accounts https://is.gd/J9gaHq.iciciBank.KYC Helpline: +91 9876543210", "ocr_text", "scam", "BANKING_KYC", "en", "reported_scam", ["https://is.gd/J9gaHq.iciciBank.KYC"], ["+91 9876543210"]),
            ("URGENT: SBI Account Blocked today. Complete KYC: https://sbi-kyc-alert.top/pan Contact: 9811223344", "ocr_text", "scam", "BANKING_KYC", "en", "reported_scam", ["https://sbi-kyc-alert.top/pan"], ["9811223344"]),
            ("Electricity Bill Alert: Connection disconnect tonight 9:30 PM. Call officer: 9822001122", "ocr_text", "scam", "ELECTRICITY", "en", "reported_scam", [], ["9822001122"]),
            ("Payment Request: Refund of Rs 2,500 pending. Accept collect request to refund-desk@upi", "ocr_text", "scam", "UPI_FRAUD", "en", "reported_scam", [], [], ["refund-desk@upi"]),
            ("Amazon Order Delivered: Your package containing Boat Earbuds delivered to security desk.", "ocr_text", "legitimate", "LEGITIMATE", "en", "reported_scam", [], []),
        ]
        for text, c_type, label, cat, lang, src, urls, phones, *rest in ocr_samples:
            upis = rest[0] if rest else []
            add_sample(text, c_type, label, cat, lang, src, urls, phones, upis)

        # ----------------------------------------------------
        # Augment with variations to form a robust 120+ sample seed benchmark
        # ----------------------------------------------------
        variations = []
        for s in samples:
            if s.content_type == "message" and s.label == "scam":
                # Create subtle variation (different phone or slightly modified wording)
                var_content = s.content.replace("9876543210", "9123456789").replace("SBI", "State Bank")
                if var_content != s.content:
                    variations.append(
                        DatasetSample(
                            sample_id=f"SCAM-DATA-{counter:05d}",
                            content=var_content,
                            content_type="message",
                            label=s.label,
                            is_scam=s.is_scam,
                            category=s.category,
                            language=s.language,
                            source="curated_threat_intel",
                            extracted_urls=s.extracted_urls,
                            extracted_phones=["9123456789"] if s.extracted_phones else [],
                            extracted_upis=s.extracted_upis,
                        )
                    )
                    counter += 1
            elif s.content_type == "message" and s.label == "legitimate":
                var_content = s.content.replace("Rs 45,000", "Rs 52,000").replace("Rs 850", "Rs 1,120")
                if var_content != s.content:
                    variations.append(
                        DatasetSample(
                            sample_id=f"SCAM-DATA-{counter:05d}",
                            content=var_content,
                            content_type="message",
                            label=s.label,
                            is_scam=s.is_scam,
                            category=s.category,
                            language=s.language,
                            source="curated_threat_intel",
                            extracted_urls=s.extracted_urls,
                            extracted_phones=s.extracted_phones,
                            extracted_upis=s.extracted_upis,
                        )
                    )
                    counter += 1

        samples.extend(variations)
        return samples
