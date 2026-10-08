from flask import Flask, render_template
import csv

app = Flask(__name__)


@app.route("/")
def dashboard():
    reports = []

    try:
        with open("security_report.csv", "r") as file:
            reader = csv.DictReader(file)
            reports = list(reader)
    except FileNotFoundError:
        pass

    return render_template("dashboard.html", reports=reports)


if __name__ == "__main__":
    app.run(debug=True)