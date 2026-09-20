export const SAMPLE_PHISHING_EML_TEXT = `Received: from mail-relay.target-corp.com (mail-relay.target-corp.com [192.0.2.1])
	by mx.target-corp.com (Postfix) with ESMTPS id 4V8d9s2k1z
	for <cfo@target-corp.com>; Mon, 7 Sep 2026 10:15:02 +0000 (UTC)
Received: from suspicious-vps.amsterdam-node.net (unknown [185.220.101.5])
	by mail-relay.target-corp.com (Postfix) with ESMTP id 3X910aBcDe
	for <cfo@target-corp.com>; Mon, 7 Sep 2026 10:14:18 +0000 (UTC)
Authentication-Results: mx.target-corp.com;
	spf=fail (sender IP is 185.220.101.5) smtp.mailfrom=executive-desk@paypa1-security.com;
	dkim=none;
	dmarc=fail (p=quarantine dis=none) header.from=paypa1-security.com
Received-SPF: fail (target-corp.com: domain of executive-desk@paypa1-security.com does not designate 185.220.101.5 as permitted sender) client-ip=185.220.101.5;
From: "CEO Executive Office" <executive-desk@paypa1-security.com>
To: "Chief Financial Officer" <cfo@target-corp.com>
Reply-To: attacker-inbox-drop@evil-domain-proxy.ru
Return-Path: <bounce-collector@paypa1-security.com>
Subject: URGENT: Outstanding Acquisition Wire Authorization Required
Date: Mon, 7 Sep 2026 10:14:00 +0000
Message-ID: <20260907101400.99812.qmail@paypa1-security.com>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="----=_Part_99182_8123912.1725704040"
X-Originating-IP: [185.220.101.5]

------=_Part_99182_8123912.1725704040
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: 7bit

<!DOCTYPE html>
<html>
<body>
<p>Dear Team,</p>
<p>Please review and authorize the attached emergency wire instructions immediately.</p>
<p>You can verify the portal authentication details at <a href="https://login.paypa1-security.com/portal/auth?session=98a12c">https://paypal.com/auth</a> or access our backup cloud server at <a href="http://185.220.101.5:8080/wire_transfer.pdf">http://backup-docs.net/file</a>.</p>
<p>Thank you,<br>Executive Management</p>
</body>
</html>

------=_Part_99182_8123912.1725704040
Content-Type: application/octet-stream; name="Urgent_Invoice_Doc.pdf.html"
Content-Disposition: attachment; filename="Urgent_Invoice_Doc.pdf.html"
Content-Transfer-Encoding: base64

PGh0bWw+PGJvZHk+PHNjcmlwdD5hbGVydCgiSGFydmVzdGluZyIpOzwvc2NyaXB0PjwvYm9keT48
L2h0bWw+
------=_Part_99182_8123912.1725704040--
`;

export const SAMPLE_CLEAN_EML_TEXT = `Received: from mail-in.company.com (mail-in.company.com [198.51.100.10])
	by mx1.company.com (Postfix) with ESMTPS id 4T92x1z9
	for <engineer@company.com>; Mon, 7 Sep 2026 08:30:15 +0000 (UTC)
Authentication-Results: mx1.company.com;
	spf=pass (sender IP is 198.51.100.10) smtp.mailfrom=notifications@partner-service.com;
	dkim=pass header.d=partner-service.com;
	dmarc=pass (p=reject dis=none) header.from=partner-service.com
From: "Partner Service Notifications" <notifications@partner-service.com>
To: <engineer@company.com>
Subject: Monthly Service Performance Metrics Summary
Date: Mon, 7 Sep 2026 08:30:00 +0000
Message-ID: <service-report-20260907@partner-service.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"

Hello Engineer,

Your system performance report for September 2026 is ready.
You can review the full summary at https://app.partner-service.com/dashboard/reports.

Best regards,
Partner Service Support Team
`;

export function createSampleEmlFile(): File {
  const blob = new Blob([SAMPLE_PHISHING_EML_TEXT], { type: 'message/rfc822' });
  return new File([blob], 'sample_phishing_wire_fraud.eml', { type: 'message/rfc822' });
}

export function createCleanEmlFile(): File {
  const blob = new Blob([SAMPLE_CLEAN_EML_TEXT], { type: 'message/rfc822' });
  return new File([blob], 'sample_clean_verified.eml', { type: 'message/rfc822' });
}
