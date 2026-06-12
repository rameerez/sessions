# frozen_string_literal: true

module Sessions
  # Base controller for the devices page. It inherits from the HOST's
  # controller (config.parent_controller, "::ApplicationController" by
  # default) so the host's layout, helpers, auth filters, locale switching
  # and exception handling all apply for free — the same integration style
  # as Devise, api_keys and chats.
  #
  # Authentication is a CHAIN, so both stacks work with zero configuration:
  #
  #   - Devise hosts: `config.authenticate_method` (:authenticate_user! by
  #     default) exists and runs.
  #   - Rails 8 omakase hosts: the inherited Authentication concern already
  #     registered `before_action :require_authentication` on the parent —
  #     parent callbacks run before ours, so anonymous visitors were
  #     redirected before this controller does anything.
  #   - Anything else: the final guard 404s rather than leaking the page.
  #
  # NOTE: the superclass is resolved when this class is autoloaded, which in
  # a booted app happens AFTER initializers — so `config.parent_controller`
  # set in config/initializers/sessions.rb is honored, and in development
  # the class reloads pick up config changes too.
  class ApplicationController < Sessions.config.parent_controller.constantize
    # The omakase Authentication concern's `request_authentication` redirects
    # with `new_session_path` — a HOST route helper, which named-helper
    # dispatch resolves against the ENGINE's routes from in here (helpers
    # call the receiver's url_for → the engine's _routes) and explodes. We
    # skip the inherited filter and re-enforce the exact same behavior
    # engine-safely in sessions_authenticate! below (raise: false makes this
    # a no-op on Devise and custom stacks that don't have the filter).
    skip_before_action :require_authentication, raise: false

    before_action :sessions_authenticate!

    helper Sessions::EngineHelper
    helper_method :sessions_current_user, :sessions_current_session

    # nil falls through to the parent controller's regular layout
    # resolution, so by default the page looks like the rest of the host.
    layout :sessions_layout

    private

    # The host's auth filters run INSIDE this engine controller (that's the
    # whole point of the parent_controller inheritance) — and they reference
    # the host's OWN route helpers (`new_session_path` in the omakase
    # concern, custom redirects in hand-rolled filters), which an isolated
    # engine can't resolve. Delegate unknown URL helpers to main_app so the
    # host's code works here unmodified — the standard engine idiom.
    def method_missing(method, *args, &block)
      if method.to_s.end_with?("_path", "_url") && main_app.respond_to?(method)
        main_app.public_send(method, *args, &block)
      else
        super
      end
    end

    def respond_to_missing?(method, include_private = false)
      (method.to_s.end_with?("_path", "_url") && main_app.respond_to?(method)) || super
    end

    # The signed-in user, via the resolver chain: configured method →
    # :current_user → ::Current.session&.user (the omakase shape).
    def sessions_current_user
      @sessions_current_user ||= sessions_resolve_user
    end

    # The registry row serving THIS request — the row the page badges as
    # "this device" and refuses to revoke.
    def sessions_current_session
      @sessions_current_session ||= Sessions.current(request)
    end

    def sessions_resolve_user
      configured = Sessions.config.current_user_method
      return send(configured) if configured && respond_to?(configured, true)
      return current_user if respond_to?(:current_user, true)

      ::Current.try(:session)&.user if defined?(::Current)
    end

    def sessions_authenticate!
      method = Sessions.config.authenticate_method
      if method && respond_to?(method, true)
        # Devise hosts (and anything that defines the configured filter).
        send(method)
        return if performed?
      elsif respond_to?(:resume_session, true)
        # Omakase hosts: the same require_authentication contract as the
        # generated concern, with the login redirect generated through
        # main_app (engine-safe).
        unless resume_session
          session[:return_to_after_authenticating] = request.url
          return redirect_to main_app.new_session_path if main_app.respond_to?(:new_session_path)

          head :not_found
          return
        end
      end

      # Privacy default: a host where no user resolves gets a plain 404 —
      # the page's existence never leaks to the unauthenticated.
      head :not_found unless sessions_current_user
    end

    def sessions_layout
      Sessions.config.layout
    end

    # The optional sudo gate (ASVS 3.3.4's "having re-entered login
    # credentials"). The host's proc receives the controller; the action
    # proceeds ONLY when the gate returns truthy without rendering:
    #
    #   - render/redirect inside the gate → blocked (your confirm flow owns
    #     the response)
    #   - return false/nil → blocked; if the gate rendered nothing, we
    #     answer 403 so a falsy gate can never fall through to the
    #     destructive action (a sudo gate fails CLOSED)
    #   - return truthy → allowed
    def sessions_reauthenticate!
      gate = Sessions.config.require_reauthentication
      return true unless gate

      allowed = gate.call(self)
      return false if performed?

      head :forbidden unless allowed
      !!allowed
    end

    # Every query goes through the OWNER's sessions — you can never touch a
    # row you don't own, even if the host's mount is misconfigured.
    def sessions_owner_sessions
      user = sessions_current_user
      if user.respond_to?(:sessions)
        user.sessions
      else
        Sessions.session_model.where(user: user)
      end
    end

    # The user's slice of the trail INCLUDING failed attempts against their
    # own identity (failures never link to an account — enumeration safety —
    # but showing a signed-in user the attempts typed against their own
    # email is exactly what a security page is for).
    def sessions_owner_events
      user = sessions_current_user
      return user.session_history if user.respond_to?(:session_history)

      # Hosts without has_sessions on the resolved user get the same slice
      # inline: owned events plus identity-matched failures.
      scope = Sessions::Event.where(authenticatable: user)
      identity = Sessions::Event.normalize_identity(user.try(:email_address) || user.try(:email))
      scope = scope.or(Sessions::Event.where(identity: identity)) if identity
      scope
    end
  end
end
