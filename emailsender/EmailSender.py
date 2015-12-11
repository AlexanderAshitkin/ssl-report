import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

CSS_TD = "border: 1px solid #D6DDE6; text-align: right; vertical-align: top; padding: 0.2em;"
CSS_TH = "border: 1px solid #828282; background-color: #BCBCBC; font-weight: bold; text-align: left; padding: 0.2em;"

FROM = 'your@yandex.ru'
TO = ["recipient@yandex.ru"]
SMTP_YANDEX_RU = "smtp.yandex.ru"
PORT = 465
PASSWORD = "Secret"

logger = logging.getLogger("EmailSender")


def send_report_email(reports):
    msg = _prepare_message(reports)

    server = smtplib.SMTP_SSL(SMTP_YANDEX_RU, PORT)
    server.login(FROM, PASSWORD)
    server.sendmail(FROM, TO, msg.as_string())
    server.quit()


def _prepare_message(reports):
    msg = MIMEMultipart('alternative')
    msg['Subject'] = "SSL Report"
    msg['From'] = FROM
    msg['To'] = FROM
    html = _format_html(reports)
    logger.debug("Email content: %s", html)
    msg.attach(MIMEText(html, "html", _charset="UTF-8"))
    return msg


def _format_html(reports):
    return u"""
        <html>
            <body>
                <table style="border: 1px solid #338BA6;border-collapse: collapse;width: 90%;">
                    <caption style="font: bold 110% Arial, Helvetica, sans-serif; color: #33517A; text-align: left; padding: 0.4em 0 0.8em 0;">SSL Report</caption>
                    <thead>
                        <tr>
                            <th scope='col' style='{css_th}'>Host</th>
                            <th scope='col' style='{css_th}'>Grade</th>
                            <th scope='col' style='{css_th}'>Grade Ignoring Trust</th>
                            <th scope='col' style='{css_th}' bgcolor="#ffcccc">Errors</th>
                            <th scope='col' style='{css_th}' bgcolor="#ffffcc">Warnings</th>
                            <th scope='col' style='{css_th}'>Supported Protocols</th>
                            <th scope='col' style='{css_th}'>Supported Ciphers</th>
                        </tr>
                    </thead>
                    <tbody>
                       {rows}
                    </tbody>
                </table>
            </body>
        </html>
    """.format(rows=format_rows(reports), css_th=CSS_TH)


def _format_grade(grade):
    if grade <= "A-":
        color = "green"
    elif grade <= "C":
        color = "#E9AB17"  # dark yellow
    else:
        color = "red"

    return u"<p style='font-size:large;color: {color}'>{grade}</p>".format(color=color, grade=grade)


def format_rows(reports):
    row_template = u"""
        <tr>
            <th scope="row" style='{css_th}''>{host}</th>
            <td style='{css_td}'>{grade}</td>
            <td style='{css_td}'>{grade_ignore_trust}</td>
            <td style='{css_td}' bgcolor="#ffcccc">{errors} </td>
            <td style='{css_td}' bgcolor="#ffffcc">{warnings}</td>
            <td style='{css_td}'>{protocols}</td>
            <td style='{css_td}'>{ciphers}</td>
       </tr>
    """
    rows = ""
    for rep in reports:
        rows += row_template.format(host=rep.host,
                                    grade=_format_grade(rep.grade),
                                    grade_ignore_trust=_format_grade(rep.grade_ignore_trust),
                                    warnings="<br>".join(rep.warnings),
                                    errors="<br>".join(rep.errors),
                                    protocols="<br>".join(rep.protocols),
                                    ciphers="<br>".join(rep.ciphers),
                                    css_td=CSS_TD,
                                    css_th=CSS_TH)
    return rows
