# frozen_string_literal: true

require 'net/http'

class ApplicationController < ActionController::API
  before_action :authenticate_agent!

  private

  def current_tenant
    current_user.tenant
  end
end
