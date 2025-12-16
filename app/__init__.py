import os
from flask import Flask
from slackeventsapi import SlackEventAdapter
from slack import WebClient
from dotenv import load_dotenv

def create_app():
    load_dotenv()
    app = Flask(__name__)

    slack_events = SlackEventAdapter(os.getenv('SIGNING_SECRET'), '/slack/events', app)
    client = WebClient(token=os.getenv('SLACK_TOKEN'))
    app.config['SLACK_CLIENT'] = client
    app.config['SLACK_EVENTS'] = slack_events
    app.config['BOT_ID'] = client.api_call("auth.test")['user_id']

    # ====== ROUTES ======
    from app.routes.elk.metric import metric_bp
    from app.routes.waf.whitelist_routes import allowwhite_bp
    from app.routes.waf.delete_ip import delete_bp
    from app.routes.waf.list_ip import list_bp
    from app.routes.waf.blacklist_routes import denyblack_bp
    from app.routes.waf.alert_report import list_not_confirm_bp
    #from app.routes.waf.investigate_routes import investigate_bp
    from app.routes.waf.close_case import close_case_bp
    from app.routes.waf.report_routes import report_bp
    from app.routes.waf.exception_pp1_routes import exception_pp1_bp
    from app.routes.waf.exception_pp2_routes import exception_pp2_bp
    from app.routes.waf.exception_pp3_routes import exception_pp3_bp
    from app.routes.waf.exception_pp4_routes import exception_pp4_bp
    from app.routes.waf.mark_fp import mark_fp_bp
    from app.routes.waf.ai_exception import ai_exception_bp

    from app.slack.events import register_message_event

    app.register_blueprint(metric_bp)
    app.register_blueprint(list_bp)
    app.register_blueprint(allowwhite_bp)
    app.register_blueprint(delete_bp)
    app.register_blueprint(denyblack_bp)
    app.register_blueprint(list_not_confirm_bp)
    #app.register_blueprint(investigate_bp)
    app.register_blueprint(close_case_bp)
    app.register_blueprint(report_bp)
    app.register_blueprint(exception_pp1_bp)
    app.register_blueprint(exception_pp2_bp)
    app.register_blueprint(exception_pp3_bp)
    app.register_blueprint(exception_pp4_bp)
    app.register_blueprint(mark_fp_bp)
    from app.routes.waf.clear_logs import clear_logs_bp
    app.register_blueprint(clear_logs_bp)
    app.register_blueprint(ai_exception_bp)
    
    register_message_event(app)
    
    return app
