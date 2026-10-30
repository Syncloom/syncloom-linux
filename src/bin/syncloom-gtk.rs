//! Syncloom for GNOME and other GTK desktops: libadwaita UI on top of the shared Rust core.
use adw::prelude::*;
use gtk::{gdk, gio, glib};
use std::cell::RefCell;
use std::future::Future;
use std::rc::Rc;
use std::sync::Arc;
use syncloom_core::client::{Auth, Client, LoginOutcome, Node};
use syncloom_core::node::NodeMeta;
use syncloom_core::state::StateDb;
use syncloom_core::sync::{SyncConfig, SyncEngine};
use syncloom_linux::config::{self, Config};

const APP_ID: &str = "world.syncloom.Syncloom";

struct Ctx {
    rt: Arc<tokio::runtime::Runtime>,
    window: adw::ApplicationWindow,
    toasts: adw::ToastOverlay,
    nav: adw::NavigationView,
    client: RefCell<Option<Arc<Client>>>,
    cfg: RefCell<Option<Config>>,
}

/// Run a future on the tokio runtime and await its result from the GTK main loop.
fn run<T: Send + 'static>(ctx: &Rc<Ctx>, fut: impl Future<Output = T> + Send + 'static) -> impl Future<Output = T> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    ctx.rt.spawn(async move {
        let _ = tx.send(fut.await);
    });
    async move { rx.await.expect("background task dropped") }
}

fn toast(ctx: &Rc<Ctx>, text: &str) {
    ctx.toasts.add_toast(adw::Toast::new(text));
}

fn fmt_bytes(n: i64) -> String {
    glib::format_size(n.max(0) as u64).to_string()
}

fn page(title: &str, child: &impl IsA<gtk::Widget>, header: Option<&adw::HeaderBar>) -> adw::NavigationPage {
    let view = adw::ToolbarView::new();
    view.add_top_bar(&header.cloned().unwrap_or_else(adw::HeaderBar::new));
    view.set_content(Some(child));
    adw::NavigationPage::builder().title(title).child(&view).build()
}

fn centered(child: &impl IsA<gtk::Widget>) -> gtk::ScrolledWindow {
    let clamp = adw::Clamp::builder().maximum_size(440).margin_top(24).margin_bottom(24).margin_start(16).margin_end(16).child(child).build();
    gtk::ScrolledWindow::builder().hscrollbar_policy(gtk::PolicyType::Never).child(&clamp).build()
}

fn logo() -> gtk::Picture {
    let tex = gdk::Texture::from_bytes(&glib::Bytes::from_static(include_bytes!("../../assets/icon-256.png"))).expect("logo");
    let p = gtk::Picture::for_paintable(&tex);
    p.set_size_request(88, 88);
    p.set_halign(gtk::Align::Center);
    p.set_can_shrink(true);
    p
}

fn heading(title: &str, sub: &str) -> gtk::Box {
    let b = gtk::Box::builder().orientation(gtk::Orientation::Vertical).spacing(6).build();
    let t = gtk::Label::builder().label(title).css_classes(["title-1"]).wrap(true).justify(gtk::Justification::Center).build();
    let s = gtk::Label::builder().label(sub).css_classes(["dim-label"]).wrap(true).justify(gtk::Justification::Center).build();
    b.append(&t);
    b.append(&s);
    b
}

fn qr_picture(data: &str) -> gtk::Picture {
    let code = qrcode::QrCode::new(data.as_bytes()).expect("qr");
    let width = code.width();
    let scale = 6usize;
    let quiet = 2usize;
    let side = (width + quiet * 2) * scale;
    let mut px = vec![255u8; side * side * 3];
    for (i, c) in code.to_colors().iter().enumerate() {
        if *c == qrcode::Color::Dark {
            let (x, y) = (i % width, i / width);
            for dy in 0..scale {
                for dx in 0..scale {
                    let o = (((y + quiet) * scale + dy) * side + (x + quiet) * scale + dx) * 3;
                    px[o..o + 3].copy_from_slice(&[20, 20, 43]);
                }
            }
        }
    }
    let tex = gdk::MemoryTexture::new(side as i32, side as i32, gdk::MemoryFormat::R8g8b8, &glib::Bytes::from_owned(px), side * 3);
    let p = gtk::Picture::for_paintable(&tex);
    p.set_size_request(200, 200);
    p.set_halign(gtk::Align::Center);
    p.add_css_class("card");
    p
}

fn pill(label: &str, suggested: bool) -> gtk::Button {
    let b = gtk::Button::builder().label(label).halign(gtk::Align::Center).build();
    b.add_css_class("pill");
    if suggested {
        b.add_css_class("suggested-action");
    }
    b
}

// ---------------------------------------------------------------- sign-in

struct Creds {
    server: String,
    username: String,
    password: String,
}

fn login_page(ctx: &Rc<Ctx>) -> adw::NavigationPage {
    let content = gtk::Box::builder().orientation(gtk::Orientation::Vertical).spacing(18).build();
    content.append(&logo());
    content.append(&heading("Welcome back", "Sign in to your encrypted storage."));
    let group = adw::PreferencesGroup::new();
    let server = adw::EntryRow::builder().title("Server").build();
    let user = adw::EntryRow::builder().title("Username").build();
    let pw = adw::PasswordEntryRow::builder().title("Password").build();
    let invite = adw::EntryRow::builder().title("Invite code").visible(false).build();
    if let Ok(c) = Config::load() {
        server.set_text(&c.server);
        user.set_text(&c.username);
    }
    for r in [server.upcast_ref::<gtk::Widget>(), user.upcast_ref(), pw.upcast_ref(), invite.upcast_ref()] {
        group.add(r);
    }
    content.append(&group);
    let go = pill("Sign in", true);
    let toggle = gtk::Button::builder().label("Create an account with an invite").css_classes(["flat"]).halign(gtk::Align::Center).build();
    content.append(&go);
    content.append(&toggle);

    let registering = Rc::new(RefCell::new(false));
    {
        let (invite, go, reg) = (invite.clone(), go.clone(), registering.clone());
        toggle.connect_clicked(move |b| {
            let r = !*reg.borrow();
            *reg.borrow_mut() = r;
            invite.set_visible(r);
            go.set_label(if r { "Create account" } else { "Sign in" });
            b.set_label(if r { "I already have an account" } else { "Create an account with an invite" });
        });
    }
    let submit = {
        let ctx = ctx.clone();
        let (server, user, pw, invite, reg, go) = (server.clone(), user.clone(), pw.clone(), invite.clone(), registering.clone(), go.clone());
        Rc::new(move || {
            let creds = Creds { server: server.text().trim().trim_end_matches('/').to_string(), username: user.text().trim().to_string(), password: pw.text().to_string() };
            let invite = invite.text().trim().to_string();
            let registering = *reg.borrow();
            if creds.server.is_empty() || creds.username.is_empty() || creds.password.is_empty() {
                return toast(&ctx, "Enter server, username and password.");
            }
            let creds = Creds { server: if creds.server.contains("://") { creds.server } else { format!("https://{}", creds.server) }, ..creds };
            go.set_sensitive(false);
            let (ctx, go) = (ctx.clone(), go.clone());
            glib::spawn_future_local(async move {
                let device = config::default_device_name();
                let auth = Auth::new(&creds.server);
                let (s, u, p, d) = (creds.server.clone(), creds.username.clone(), creds.password.clone(), device.clone());
                let result = if registering {
                    run(&ctx, async move { auth.register(&u, &p, if invite.is_empty() { None } else { Some(&invite) }, &d).await.map(|r| (r.outcome, Some(r.recovery_key))) }).await
                } else {
                    run(&ctx, async move { auth.login(&u, &p, &d).await.map(|o| (o, None)) }).await
                };
                let _ = s;
                go.set_sensitive(true);
                match result {
                    Ok((outcome, Some(key))) => show_recovery_key(&ctx, creds, outcome, key),
                    Ok((outcome, None)) => handle_outcome(&ctx, creds, outcome),
                    Err(e) => toast(&ctx, &e.to_string()),
                }
            });
        })
    };
    {
        let s = submit.clone();
        go.connect_clicked(move |_| s());
    }
    for row in [&server, &user, &invite] {
        let s = submit.clone();
        row.connect_entry_activated(move |_| s());
    }
    {
        let s = submit.clone();
        pw.connect_entry_activated(move |_| s());
    }
    page("Syncloom", &centered(&content), None)
}

fn show_recovery_key(ctx: &Rc<Ctx>, creds: Creds, outcome: LoginOutcome, key: String) {
    let content = gtk::Box::builder().orientation(gtk::Orientation::Vertical).spacing(18).build();
    content.append(&heading("Save your recovery key", "If you forget your password, this key is the only way to get your files back. Not even an administrator can help."));
    let label = gtk::Label::builder().label(key.as_bytes().chunks(17).map(|c| String::from_utf8_lossy(c).to_string()).collect::<Vec<_>>().join("\n")).selectable(true).css_classes(["monospace", "title-4"]).justify(gtk::Justification::Center).build();
    let frame = gtk::Frame::builder().child(&label).build();
    label.set_margin_top(14);
    label.set_margin_bottom(14);
    content.append(&frame);
    let copy = gtk::Button::builder().label("Copy").halign(gtk::Align::Center).build();
    {
        let k = key.clone();
        copy.connect_clicked(move |b| b.clipboard().set_text(&k));
    }
    content.append(&copy);
    let ack = gtk::CheckButton::builder().label("I have stored it somewhere safe").halign(gtk::Align::Center).build();
    content.append(&ack);
    let next = pill("Continue", true);
    next.set_sensitive(false);
    ack.connect_toggled({
        let n = next.clone();
        move |a| n.set_sensitive(a.is_active())
    });
    let (ctx2, creds_cell, outcome_cell) = (ctx.clone(), Rc::new(RefCell::new(Some(creds))), Rc::new(RefCell::new(Some(outcome))));
    next.connect_clicked(move |_| {
        if let (Some(c), Some(o)) = (creds_cell.borrow_mut().take(), outcome_cell.borrow_mut().take()) {
            handle_outcome(&ctx2, c, o);
        }
    });
    content.append(&next);
    ctx.nav.push(&page("Recovery key", &centered(&content), None));
}

fn handle_outcome(ctx: &Rc<Ctx>, creds: Creds, outcome: LoginOutcome) {
    match outcome {
        LoginOutcome::Ok { token } => finish(ctx, creds, token),
        LoginOutcome::MfaRequired { token, methods } => mfa_page(ctx, creds, token, methods),
        LoginOutcome::EnrollRequired { token } => enroll_page(ctx, creds, token),
    }
}

fn mfa_page(ctx: &Rc<Ctx>, creds: Creds, token: String, methods: Vec<String>) {
    let content = gtk::Box::builder().orientation(gtk::Orientation::Vertical).spacing(18).build();
    content.append(&heading("Verify it’s you", "Use any one of your second factors."));
    let group = adw::PreferencesGroup::new();
    let code = adw::EntryRow::builder().title("6-digit code").build();
    let recovery = adw::SwitchRow::builder().title("Use a recovery code instead").build();
    group.add(&code);
    group.add(&recovery);
    content.append(&group);
    if !methods.iter().any(|m| m == "totp") {
        let note = gtk::Label::builder().label("This account only has security keys. This app cannot use them; enter a recovery code or sign in through the web app.").wrap(true).css_classes(["dim-label"]).build();
        content.append(&note);
        recovery.set_active(true);
    }
    let go = pill("Verify", true);
    content.append(&go);
    let creds = Rc::new(creds);
    let submit = {
        let (ctx, creds, code, recovery, go) = (ctx.clone(), creds, code.clone(), recovery.clone(), go.clone());
        Rc::new(move || {
            let (c, method) = (code.text().trim().to_string(), if recovery.is_active() { "recovery" } else { "totp" });
            if c.is_empty() {
                return;
            }
            go.set_sensitive(false);
            let (ctx, creds, token, go) = (ctx.clone(), creds.clone(), token.clone(), go.clone());
            glib::spawn_future_local(async move {
                let auth = Auth::new(&creds.server);
                let device = config::default_device_name();
                let r = run(&ctx, async move { auth.mfa_verify(&token, method, &c, &device).await }).await;
                go.set_sensitive(true);
                match r {
                    Ok(t) => finish(&ctx, Creds { server: creds.server.clone(), username: creds.username.clone(), password: creds.password.clone() }, t),
                    Err(e) => toast(&ctx, &e.to_string()),
                }
            });
        })
    };
    {
        let s = submit.clone();
        go.connect_clicked(move |_| s());
    }
    {
        let s = submit.clone();
        code.connect_entry_activated(move |_| s());
    }
    ctx.nav.push(&page("Verification", &centered(&content), None));
}

fn enroll_page(ctx: &Rc<Ctx>, creds: Creds, token: String) {
    let content = gtk::Box::builder().orientation(gtk::Orientation::Vertical).spacing(14).build();
    content.append(&heading("Add a second factor", "Scan the code with your authenticator app, then enter the 6 digits. You can add more factors later."));
    let holder = gtk::Box::builder().orientation(gtk::Orientation::Vertical).spacing(14).build();
    content.append(&holder);
    let creds = Rc::new(creds);
    let ctx2 = ctx.clone();
    let token2 = token.clone();
    let creds2 = creds.clone();
    glib::spawn_future_local(async move {
        let (ctx, auth, t) = (ctx2.clone(), Auth::new(&creds2.server), token2.clone());
        let setup = match run(&ctx, async move { auth.totp_setup(&t, &format!("{} authenticator", config::default_device_name())).await }).await {
            Ok(s) => s,
            Err(e) => return toast(&ctx2, &e.to_string()),
        };
        holder.append(&qr_picture(&setup.otpauth_url));
        let secret = gtk::Label::builder().label(setup.secret.as_bytes().chunks(4).map(|c| String::from_utf8_lossy(c).to_string()).collect::<Vec<_>>().join(" ")).selectable(true).css_classes(["monospace"]).build();
        holder.append(&secret);
        let group = adw::PreferencesGroup::new();
        let code = adw::EntryRow::builder().title("6-digit code").build();
        group.add(&code);
        holder.append(&group);
        let go = pill("Verify and continue", true);
        holder.append(&go);
        let (id, ctx3, creds3) = (setup.id.clone(), ctx2.clone(), creds2.clone());
        go.connect_clicked(move |b| {
            let c = code.text().replace(' ', "");
            b.set_sensitive(false);
            let (ctx, creds, token, id, b) = (ctx3.clone(), creds3.clone(), token2.clone(), id.clone(), b.clone());
            glib::spawn_future_local(async move {
                let auth = Auth::new(&creds.server);
                let device = config::default_device_name();
                let r = run(&ctx, async move { auth.totp_confirm(&token, &id, &c, &device).await }).await;
                b.set_sensitive(true);
                match r {
                    Ok(done) => show_codes(&ctx, Creds { server: creds.server.clone(), username: creds.username.clone(), password: creds.password.clone() }, done.recovery_codes, done.token),
                    Err(e) => toast(&ctx, &e.to_string()),
                }
            });
        });
    });
    ctx.nav.push(&page("Second factor", &centered(&content), None));
}

fn show_codes(ctx: &Rc<Ctx>, creds: Creds, codes: Vec<String>, token: String) {
    let content = gtk::Box::builder().orientation(gtk::Orientation::Vertical).spacing(18).build();
    content.append(&heading("You are protected", "Keep these one-time recovery codes in case you lose your devices."));
    if !codes.is_empty() {
        let label = gtk::Label::builder().label(codes.join("\n")).selectable(true).css_classes(["monospace"]).justify(gtk::Justification::Center).build();
        let frame = gtk::Frame::builder().child(&label).build();
        label.set_margin_top(12);
        label.set_margin_bottom(12);
        content.append(&frame);
        let copy = gtk::Button::builder().label("Copy all").halign(gtk::Align::Center).build();
        let text = codes.join("\n");
        copy.connect_clicked(move |b| b.clipboard().set_text(&text));
        content.append(&copy);
    }
    let go = pill("Open my files", true);
    let (ctx2, cell) = (ctx.clone(), Rc::new(RefCell::new(Some(creds))));
    go.connect_clicked(move |_| {
        if let Some(c) = cell.borrow_mut().take() {
            finish(&ctx2, c, token.clone());
        }
    });
    content.append(&go);
    ctx.nav.push(&page("Recovery codes", &centered(&content), None));
}

fn finish(ctx: &Rc<Ctx>, creds: Creds, token: String) {
    let ctx = ctx.clone();
    glib::spawn_future_local(async move {
        let (s, t, p) = (creds.server.clone(), token.clone(), creds.password.clone());
        match run(&ctx, async move { Client::connect(&s, &t, &p).await }).await {
            Ok(client) => {
                let _ = config::store_vault(&creds.server, &creds.username, client.vault());
                let cfg = Config { server: creds.server, username: creds.username.to_lowercase(), token, sync_dir: config::default_sync_dir(), device: config::default_device_name() };
                let _ = cfg.save();
                *ctx.cfg.borrow_mut() = Some(cfg);
                *ctx.client.borrow_mut() = Some(Arc::new(client));
                open_main(&ctx);
            }
            Err(e) => toast(&ctx, &format!("Could not unlock your vault: {e}")),
        }
    });
}

// ---------------------------------------------------------------- files

struct Browser {
    ctx: Rc<Ctx>,
    list: gtk::ListBox,
    stack: RefCell<Vec<(Option<String>, String)>>,
    title: adw::WindowTitle,
    back: gtk::Button,
    empty: adw::StatusPage,
    content: gtk::Stack,
}

fn open_main(ctx: &Rc<Ctx>) {
    let b = Rc::new(Browser {
        ctx: ctx.clone(),
        list: gtk::ListBox::builder().selection_mode(gtk::SelectionMode::None).css_classes(["boxed-list"]).build(),
        stack: RefCell::new(vec![(None, "Files".into())]),
        title: adw::WindowTitle::new("Files", ""),
        back: gtk::Button::builder().icon_name("go-previous-symbolic").tooltip_text("Back").visible(false).build(),
        empty: adw::StatusPage::builder().icon_name("folder-symbolic").title("This folder is empty").description("Use Upload to add files. They are encrypted before they leave this computer.").build(),
        content: gtk::Stack::new(),
    });
    let header = adw::HeaderBar::new();
    header.set_title_widget(Some(&b.title));
    header.pack_start(&b.back);
    let menu = gio::Menu::new();
    menu.append(Some("Security & account"), Some("app.settings"));
    menu.append(Some("Sign out"), Some("app.signout"));
    let menu_btn = gtk::MenuButton::builder().icon_name("open-menu-symbolic").menu_model(&menu).primary(true).build();
    header.pack_end(&menu_btn);
    let upload = gtk::Button::builder().icon_name("document-send-symbolic").tooltip_text("Upload files").build();
    let newf = gtk::Button::builder().icon_name("folder-new-symbolic").tooltip_text("New folder").build();
    let sync = gtk::Button::builder().icon_name("emblem-synchronizing-symbolic").tooltip_text("Sync folder now").build();
    header.pack_end(&upload);
    header.pack_end(&newf);
    header.pack_end(&sync);

    let scroller = gtk::ScrolledWindow::builder().child(&adw::Clamp::builder().maximum_size(900).margin_top(18).margin_bottom(18).margin_start(14).margin_end(14).child(&b.list).build()).vexpand(true).build();
    b.content.add_named(&scroller, Some("list"));
    b.content.add_named(&b.empty, Some("empty"));
    let spinner = gtk::Spinner::builder().spinning(true).halign(gtk::Align::Center).valign(gtk::Align::Center).width_request(32).height_request(32).build();
    b.content.add_named(&spinner, Some("loading"));
    ctx.nav.replace(&[page("Files", &b.content, Some(&header))]);

    b.back.connect_clicked({
        let b = b.clone();
        move |_| {
            b.stack.borrow_mut().pop();
            b.reload();
        }
    });
    newf.connect_clicked({
        let b = b.clone();
        move |_| b.new_folder()
    });
    upload.connect_clicked({
        let b = b.clone();
        move |_| b.upload()
    });
    sync.connect_clicked({
        let b = b.clone();
        move |btn| b.sync_now(btn)
    });
    let app = ctx.window.application().expect("application");
    let a = gio::SimpleAction::new("settings", None);
    {
        let ctx = ctx.clone();
        a.connect_activate(move |_, _| settings_dialog(&ctx));
    }
    app.add_action(&a);
    let s = gio::SimpleAction::new("signout", None);
    {
        let ctx = ctx.clone();
        s.connect_activate(move |_, _| sign_out(&ctx));
    }
    app.add_action(&s);
    b.reload();
}

impl Browser {
    fn client(&self) -> Arc<Client> {
        self.ctx.client.borrow().clone().expect("signed in")
    }
    fn current(&self) -> Option<String> {
        self.stack.borrow().last().and_then(|(id, _)| id.clone())
    }

    fn reload(self: &Rc<Self>) {
        let me = self.clone();
        {
            let st = me.stack.borrow();
            me.title.set_title(&st.last().map(|(_, n)| n.clone()).unwrap_or_default());
            me.back.set_visible(st.len() > 1);
        }
        me.content.set_visible_child_name("loading");
        glib::spawn_future_local(async move {
            let (c, parent) = (me.client(), me.current());
            match run(&me.ctx, async move { c.list(parent.as_deref()).await }).await {
                Ok(mut nodes) => {
                    nodes.sort_by(|a, b| (!a.is_folder()).cmp(&!b.is_folder()).then(a.name.to_lowercase().cmp(&b.name.to_lowercase())));
                    me.populate(nodes);
                }
                Err(e) => {
                    toast(&me.ctx, &e.to_string());
                    me.content.set_visible_child_name("empty");
                }
            }
        });
    }

    fn populate(self: &Rc<Self>, nodes: Vec<Node>) {
        while let Some(r) = self.list.first_child() {
            self.list.remove(&r);
        }
        if nodes.is_empty() {
            return self.content.set_visible_child_name("empty");
        }
        for n in nodes {
            let row = adw::ActionRow::builder().title(glib::markup_escape_text(&n.name)).build();
            let sub = if n.is_folder() { "Folder".to_string() } else if n.head_version.is_none() { "Uploading…".into() } else { fmt_bytes(n.size) };
            row.set_subtitle(&sub);
            row.add_prefix(&gtk::Image::from_icon_name(if n.is_folder() { "folder-symbolic" } else { "text-x-generic-symbolic" }));
            if n.is_folder() {
                row.set_activatable(true);
                row.add_suffix(&gtk::Image::from_icon_name("go-next-symbolic"));
                let (me, id, name) = (self.clone(), n.id.clone(), n.name.clone());
                row.connect_activated(move |_| {
                    me.stack.borrow_mut().push((Some(id.clone()), name.clone()));
                    me.reload();
                });
            } else {
                let dl = gtk::Button::builder().icon_name("document-save-symbolic").tooltip_text("Download").valign(gtk::Align::Center).css_classes(["flat"]).build();
                let (me, node) = (self.clone(), n.clone());
                dl.connect_clicked(move |_| me.download(node.clone()));
                row.add_suffix(&dl);
            }
            let del = gtk::Button::builder().icon_name("user-trash-symbolic").tooltip_text("Move to trash").valign(gtk::Align::Center).css_classes(["flat"]).build();
            let (me, id) = (self.clone(), n.id.clone());
            del.connect_clicked(move |_| {
                let (me, id) = (me.clone(), id.clone());
                glib::spawn_future_local(async move {
                    let c = me.client();
                    match run(&me.ctx, async move { c.trash(&id).await }).await {
                        Ok(()) => me.reload(),
                        Err(e) => toast(&me.ctx, &e.to_string()),
                    }
                });
            });
            row.add_suffix(&del);
            self.list.append(&row);
        }
        self.content.set_visible_child_name("list");
    }

    fn new_folder(self: &Rc<Self>) {
        let dialog = adw::AlertDialog::builder().heading("New folder").build();
        let entry = gtk::Entry::builder().text("Untitled folder").activates_default(true).build();
        dialog.set_extra_child(Some(&entry));
        dialog.add_responses(&[("cancel", "Cancel"), ("create", "Create")]);
        dialog.set_response_appearance("create", adw::ResponseAppearance::Suggested);
        dialog.set_default_response(Some("create"));
        let me = self.clone();
        dialog.connect_response(None, move |_, r| {
            if r != "create" {
                return;
            }
            let (me, name) = (me.clone(), entry.text().to_string());
            glib::spawn_future_local(async move {
                let (c, parent) = (me.client(), me.current());
                match run(&me.ctx, async move { c.create_folder(parent.as_deref(), &name).await }).await {
                    Ok(_) => me.reload(),
                    Err(e) => toast(&me.ctx, &e.to_string()),
                }
            });
        });
        dialog.present(Some(&self.ctx.window));
    }

    fn upload(self: &Rc<Self>) {
        let me = self.clone();
        glib::spawn_future_local(async move {
            let Ok(files) = gtk::FileDialog::builder().title("Upload files").build().open_multiple_future(Some(&me.ctx.window)).await else { return };
            let mut paths = vec![];
            for i in 0..files.n_items() {
                if let Some(f) = files.item(i).and_downcast::<gio::File>().and_then(|f| f.path()) {
                    paths.push(f);
                }
            }
            let (c, parent) = (me.client(), me.current());
            toast(&me.ctx, &format!("Uploading {} file(s)…", paths.len()));
            let res = run(&me.ctx, async move {
                for p in paths {
                    let name = p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
                    let mtime = std::fs::metadata(&p).and_then(|m| m.modified()).ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_millis() as i64).unwrap_or(0);
                    let n = c.create_file_node(parent.as_deref(), &name, &NodeMeta { mtime_ms: mtime, executable: false }).await?;
                    c.upload_version(&n.id, None, std::fs::File::open(&p)?).await?;
                }
                Ok::<_, syncloom_core::Error>(())
            })
            .await;
            match res {
                Ok(()) => toast(&me.ctx, "Upload complete"),
                Err(e) => toast(&me.ctx, &e.to_string()),
            }
            me.reload();
        });
    }

    fn download(self: &Rc<Self>, node: Node) {
        let me = self.clone();
        glib::spawn_future_local(async move {
            let Ok(file) = gtk::FileDialog::builder().title("Save file").initial_name(&node.name).build().save_future(Some(&me.ctx.window)).await else { return };
            let Some(path) = file.path() else { return };
            let c = me.client();
            let res = run(&me.ctx, async move {
                let mut out = std::fs::File::create(&path)?;
                c.download_to(&node.id, None, &mut out).await.map(|_| ())
            })
            .await;
            toast(&me.ctx, &match res {
                Ok(()) => "Saved".to_string(),
                Err(e) => e.to_string(),
            });
        });
    }

    fn sync_now(self: &Rc<Self>, btn: &gtk::Button) {
        let (me, btn) = (self.clone(), btn.clone());
        btn.set_sensitive(false);
        glib::spawn_future_local(async move {
            let (c, cfg) = (me.client(), me.ctx.cfg.borrow().clone().expect("config"));
            let res = run(&me.ctx, async move {
                let mut e = SyncEngine::new(c, SyncConfig { root: cfg.sync_dir.clone(), device: cfg.device.clone() }, StateDb::open(&config::state_db_path())?)?;
                e.sync_once().await
            })
            .await;
            btn.set_sensitive(true);
            match res {
                Ok(r) => toast(&me.ctx, &format!("Synced: {} up, {} down, {} merged, {} conflict copies", r.uploaded.len(), r.downloaded.len(), r.merged.len(), r.conflicts.len())),
                Err(e) => toast(&me.ctx, &e.to_string()),
            }
            me.reload();
        });
    }
}

// ---------------------------------------------------------------- settings

fn settings_dialog(ctx: &Rc<Ctx>) {
    let dialog = adw::PreferencesDialog::builder().title("Security & account").build();
    let p = adw::PreferencesPage::new();
    let account = adw::PreferencesGroup::builder().title("Account").build();
    let methods = adw::PreferencesGroup::builder().title("Two-step verification").description("Add as many as you like. Any one of them signs you in. Security keys can be added in the web app.").build();
    p.add(&account);
    p.add(&methods);
    dialog.add(&p);
    let (ctx2, methods2, account2) = (ctx.clone(), methods.clone(), account.clone());
    glib::spawn_future_local(async move {
        let c = ctx2.client.borrow().clone().expect("client");
        let c2 = c.clone();
        let me = run(&ctx2, async move { c2.me().await }).await;
        if let Ok(me) = me {
            let used = fmt_bytes(me.user.used_bytes);
            for (t, v) in [("Server", ctx2.cfg.borrow().as_ref().map(|c| c.server.clone()).unwrap_or_default()), ("User", me.user.username.clone()), ("Storage", match me.user.quota_bytes { Some(q) => format!("{used} of {}", fmt_bytes(q)), None => used })] {
                let row = adw::ActionRow::builder().title(t).subtitle(glib::markup_escape_text(&v)).subtitle_selectable(true).build();
                account2.add(&row);
            }
        }
        let list = run(&ctx2, async move { c.mfa_methods().await }).await.unwrap_or_default();
        for m in list {
            let row = adw::ActionRow::builder().title(glib::markup_escape_text(&m.name)).subtitle(if m.kind == "webauthn" { "Security key" } else { "Authenticator app" }).build();
            row.add_prefix(&gtk::Image::from_icon_name(if m.kind == "webauthn" { "security-high-symbolic" } else { "preferences-system-time-symbolic" }));
            methods2.add(&row);
        }
    });
    dialog.present(Some(&ctx.window));
}

fn sign_out(ctx: &Rc<Ctx>) {
    let ctx = ctx.clone();
    glib::spawn_future_local(async move {
        if let (Some(c), Some(cfg)) = (ctx.client.borrow_mut().take(), ctx.cfg.borrow_mut().take()) {
            let _ = run(&ctx, async move { c.logout().await }).await;
            config::delete_vault(&cfg.server, &cfg.username);
        }
        let _ = Config::delete();
        ctx.nav.replace(&[login_page(&ctx)]);
    });
}

fn build_ui(app: &adw::Application) {
    let rt = Arc::new(tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().expect("runtime"));
    let nav = adw::NavigationView::new();
    let toasts = adw::ToastOverlay::new();
    toasts.set_child(Some(&nav));
    let window = adw::ApplicationWindow::builder().application(app).title("Syncloom").default_width(960).default_height(680).content(&toasts).build();
    let ctx = Rc::new(Ctx { rt, window: window.clone(), toasts, nav: nav.clone(), client: RefCell::new(None), cfg: RefCell::new(None) });
    nav.add(&login_page(&ctx));
    window.present();

    // resume a previous session
    if let Ok(cfg) = Config::load() {
        if let Ok(vault) = config::load_vault(&cfg.server, &cfg.username) {
            let ctx = ctx.clone();
            glib::spawn_future_local(async move {
                let (s, t) = (cfg.server.clone(), cfg.token.clone());
                if let Ok(client) = run(&ctx, async move { Client::with_vault(&s, &t, vault).await }).await {
                    *ctx.cfg.borrow_mut() = Some(cfg);
                    *ctx.client.borrow_mut() = Some(Arc::new(client));
                    open_main(&ctx);
                }
            });
        }
    }
}

fn main() -> glib::ExitCode {
    let app = adw::Application::builder().application_id(APP_ID).build();
    app.connect_activate(build_ui);
    app.run()
}
