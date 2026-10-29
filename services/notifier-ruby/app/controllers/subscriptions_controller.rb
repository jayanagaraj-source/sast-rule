# frozen_string_literal: true

# Notification subscriptions: agents subscribe to cases whose subject matches a filter.
class SubscriptionsController < ApplicationController
  MAX_FILTER_LENGTH = 100
  STATUS_URL = 'https://status.partner-crm.example/api/v2/status.json'
  DEFAULT_PREFS = { channel: 'email', digest: 'daily' }.freeze

  def preview
    cases = current_tenant.cases.order(updated_at: :desc).limit(500)
    # CASE: R11-GAP-09
    # todoruleid: SAST-011 | src: params[:q] | sink: Regexp.new + match? | attacker regex; SAST-011 patterns do not match Ruby's Regexp.new
    filter = Regexp.new(params[:q])
    render json: cases.select { |c| filter.match?(c.subject) }.map(&:id)
  end

  def preview_interpolated
    cases = current_tenant.cases.order(updated_at: :desc).limit(500)
    # CASE: R11-GAP-10
    # todoruleid: SAST-011 | src: params[:q] | sink: interpolated regex literal | /#{...}/ compiles user input as a pattern
    render json: cases.select { |c| c.subject =~ /#{params[:q]}/i }.map(&:id)
  end

  def preview_literal
    term = params[:q].to_s[0, MAX_FILTER_LENGTH]
    # CASE: R11-FP-19
    # ok: SAST-011 | src: params[:q] (escaped, bounded) | sink: Regexp.new | Regexp.escape makes the input literal
    filter = Regexp.new(Regexp.escape(term), Regexp::IGNORECASE)
    render json: current_tenant.cases.limit(500).select { |c| filter.match?(c.subject) }.map(&:id)
  end

  def preview_with_timeout
    # CASE: R11-FP-20
    # ok: SAST-011 | src: params[:q] (admin only) | sink: Regexp.new with timeout | Ruby 3.2 per-regex timeout bounds backtracking to 50 ms
    filter = Regexp.new(params[:q].to_s, timeout: 0.05)
    render json: current_tenant.cases.limit(500).select { |c| filter.match?(c.subject) }.map(&:id)
  rescue Regexp::TimeoutError
    render json: { error: 'filter too complex' }, status: :unprocessable_entity
  end

  def update_prefs
    # CASE: R08-FP-27
    # ok: JS-002 | src: permitted params | sink: Hash#merge | Ruby hash merge with strong parameters; the JS-only rule must stay silent
    prefs = DEFAULT_PREFS.merge(params.require(:prefs).permit(:channel, :digest).to_h.symbolize_keys)
    current_user.update!(notification_prefs: prefs)
    # CASE: R04-FP-15
    # ok: TG-TAINT-JS-SSRF | src: constant URL | sink: Net::HTTP.get | fixed host in Ruby; JS-only taint rule must stay silent
    status = Net::HTTP.get(URI(STATUS_URL))
    render json: { prefs: prefs, partner_status: JSON.parse(status) }
  end
end
