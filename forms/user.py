from flask_login import UserMixin


class User(UserMixin):
    def __init__(self, user_id, username, is_admin=False, enable_pagination=False, show_timer=False, show_otp_type=True, show_content_titles=True, show_emails=0, show_company=False):  
        self.id = user_id
        self.username = username
        self.is_admin = is_admin
        self.enable_pagination = enable_pagination
        self.show_timer = show_timer
        self.show_otp_type = show_otp_type
        self.show_content_titles = show_content_titles
        self.show_emails = bool(show_emails)
        self.show_company = bool(show_company)