import csv


def get_recommendation(threat):
    if threat == "Brute Force Attack":
        return "Block the source IP, review the affected account, and enable multi-factor authentication."

    if threat == "Port Scanning":
        return "Investigate the source IP and restrict unnecessary exposed network ports."

    return "Investigate the activity and review security logs."


def detect_threats(log_file):
    failed = {}
    scans = {}
    reports = []

    with open(log_file, "r") as file:
        for line in file:

            if "LOGIN_FAILED" in line:
                ip = line.split("IP=")[1].split()[0]
                failed[ip] = failed.get(ip, 0) + 1

            if "PORT_SCAN" in line:
                ip = line.split("IP=")[1].split()[0]
                scans[ip] = scans.get(ip, 0) + 1

    for ip, count in failed.items():
        if count >= 5:
            threat = "Brute Force Attack"

            reports.append([
                threat,
                ip,
                "HIGH",
                90,
                get_recommendation(threat)
            ])

    for ip, count in scans.items():
        if count >= 5:
            threat = "Port Scanning"

            reports.append([
                threat,
                ip,
                "HIGH",
                85,
                get_recommendation(threat)
            ])

    print("\n===== CYBERSOC LITE =====")

    for report in reports:
        print("\n[ALERT]")
        print("Threat:", report[0])
        print("IP:", report[1])
        print("Severity:", report[2])
        print("Risk Score:", str(report[3]) + "/100")
        print("Recommendation:", report[4])

    with open("security_report.csv", "w", newline="") as file:
        writer = csv.writer(file)

        writer.writerow([
            "Threat",
            "IP Address",
            "Severity",
            "Risk Score",
            "Recommendation"
        ])

        writer.writerows(reports)

    print("\nSecurity report created: security_report.csv")