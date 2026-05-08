from django.urls import path
from . import views

urlpatterns = [
    path("",                                       views.login_view,             name="login"),
    path("register/",                              views.register_view,          name="register"),
    path("logout/",                                views.logout_view,            name="logout"),
    path("otp/",                                   views.otp_verify_view,        name="otp_verify"),

    path("home/",                                  views.index_view,             name="index"),
    path("feed/",                                  views.feed_view,              name="feed"),
    path("profile/",                               views.profile_update_view,    name="profile_update"),

    path("post/new/",                              views.post_new_view,          name="post_new"),
    path("post/<int:post_id>/",                    views.post_detail_view,       name="post_detail"),
    path("post/<int:post_id>/edit/",               views.post_edit_view,         name="post_edit"),
    path("post/<int:post_id>/delete/",             views.post_delete_view,       name="post_delete"),
    path("post/<int:post_id>/toggle/",             views.post_toggle_visibility, name="post_toggle"),

    path("messages/",                              views.messages_inbox_view,    name="messages_inbox"),
    path("messages/unlock/",                       views.vault_unlock_view,      name="vault_unlock"),
    path("messages/new/",                          views.message_new_view,       name="message_new"),
    path("messages/<int:msg_id>/",                 views.message_detail_view,    name="message_detail"),

    path("profile/upload-picture/",  views.upload_profile_picture_view, name="upload_profile_picture"),
    path("profile/verify-picture/",  views.verify_profile_picture_view, name="verify_profile_picture"),
    path("profile/picture/<int:user_id>/", views.profile_picture_view, name="profile_picture"),

    path("admin-panel/",                           views.admin_dashboard_view,   name="admin_dashboard"),
    path("admin-panel/delete-user/<int:user_id>/", views.admin_delete_user_view, name="admin_delete_user"),
    path("admin-panel/delete-post/<int:post_id>/", views.admin_delete_post_view, name="admin_delete_post"),
    path("admin-panel/change-role/<int:user_id>/", views.admin_change_role_view, name="admin_change_role"),
]