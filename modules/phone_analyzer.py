import phonenumbers
from phonenumbers import geocoder, carrier, timezone
from datetime import datetime

def run_phone_recon(phone_number):
    try:
        # Parse the phone number
        # Default region 'US' if no + is provided, though we encourage E.164 format
        if not phone_number.startswith('+'):
            phone_number = '+' + phone_number
            
        parsed_number = phonenumbers.parse(phone_number)
        
        # Check if it's a valid number
        is_valid = phonenumbers.is_valid_number(parsed_number)
        is_possible = phonenumbers.is_possible_number(parsed_number)
        
        if not is_valid:
            return {
                "phone_number": phone_number,
                "valid": False,
                "error": "Invalid phone number format or structure."
            }

        # Format number
        e164_format = phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.E164)
        intl_format = phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
        
        # Geolocation
        location = geocoder.description_for_number(parsed_number, "en")
        
        # Carrier
        network = carrier.name_for_number(parsed_number, "en")
        
        # Timezone
        timezones = timezone.time_zones_for_number(parsed_number)
        tz_str = ", ".join(timezones) if timezones else "Unknown"
        
        # Line Type (Basic inference based on phonenumbers enum, though somewhat limited without external API)
        number_type = phonenumbers.number_type(parsed_number)
        type_mapping = {
            phonenumbers.PhoneNumberType.MOBILE: "Mobile",
            phonenumbers.PhoneNumberType.FIXED_LINE: "Landline",
            phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "Landline/Mobile",
            phonenumbers.PhoneNumberType.VOIP: "VoIP (Internet Phone)",
            phonenumbers.PhoneNumberType.TOLL_FREE: "Toll-Free",
            phonenumbers.PhoneNumberType.PREMIUM_RATE: "Premium Rate",
            phonenumbers.PhoneNumberType.SHARED_COST: "Shared Cost",
            phonenumbers.PhoneNumberType.PAGER: "Pager",
            phonenumbers.PhoneNumberType.PERSONAL_NUMBER: "Personal Number",
            phonenumbers.PhoneNumberType.UAN: "Company/UAN",
            phonenumbers.PhoneNumberType.UNKNOWN: "Unknown"
        }
        line_type_str = type_mapping.get(number_type, "Unknown")
        
        # Risk Evaluation
        threat_score = 0
        threat_level = "Low"
        warnings = []
        
        if number_type == phonenumbers.PhoneNumberType.VOIP:
            threat_score += 40
            warnings.append("VoIP number detected. Often used for disposable numbers, spam, or scams.")
            threat_level = "Medium"
            
        if number_type == phonenumbers.PhoneNumberType.PREMIUM_RATE:
            threat_score += 30
            warnings.append("Premium rate number detected. Proceed with caution to avoid charges.")
            threat_level = "Medium"
            
        if not location:
            threat_score += 15
            warnings.append("No geographical location could be resolved for this block.")
            
        if not network and number_type == phonenumbers.PhoneNumberType.MOBILE:
            threat_score += 10
            warnings.append("Carrier could not be identified.")
            
        if threat_score >= 60:
            threat_level = "High"

        # Generate OSINT Links
        clean_number = f"+{parsed_number.country_code}{parsed_number.national_number}"
        links = {
            "google_dork": f"https://www.google.com/search?q=%22{clean_number}%22+OR+%22{intl_format}%22",
            "whatsapp": f"https://wa.me/{parsed_number.country_code}{parsed_number.national_number}",
            "telegram": f"https://t.me/{clean_number}",
            "truecaller": f"https://www.truecaller.com/search/{str(parsed_number.country_code)}/{parsed_number.national_number}"
        }

        return {
            "valid": True,
            "phone_number": e164_format,
            "formatted": intl_format,
            "location": location or "Unknown",
            "carrier": network or "Unknown",
            "line_type": line_type_str,
            "timezones": tz_str,
            "country_code": f"+{parsed_number.country_code}",
            "threat_score": min(threat_score, 100),
            "threat_level": threat_level,
            "warnings": warnings,
            "links": links,
            "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
    except phonenumbers.NumberParseException as e:
        return {
            "phone_number": phone_number,
            "valid": False,
            "error": str(e)
        }
    except Exception as e:
        return {
            "phone_number": phone_number,
            "valid": False,
            "error": "An unexpected error occurred during processing."
        }
