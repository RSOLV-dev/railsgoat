# frozen_string_literal: true
class MessagesController < ApplicationController

  def index
    @messages = current_user.messages
    @message = Message.new
    sleep(3)
  end

  def show
    @message = Message.where(id: params[:id]).first
  end

  def destroy
    message = Message.where(id: params[:id]).first

    if message.destroy
      Rails.logger.info("[SECURITY] User #{current_user.id} deleted message #{params[:id]} from IP #{request.remote_ip}")
      flash[:success] = "Your message has been deleted."
      redirect_to user_messages_path(user_id: current_user.id)
    else
      Rails.logger.warn("[SECURITY] Failed message deletion attempt by user #{current_user.id} for message_id #{params[:id]} from IP #{request.remote_ip}")
      flash[:error] = "Could not delete message."
    end
  end

  def create
    if Message.create(message_params)
      respond_to do |format|
        format.html { redirect_to user_messages_path(user_id: current_user.id) }
        format.json { render json: {msg: "success"} }
      end
    else
      respond_to do |format|
        format.html { redirect_to user_messages_path }
        format.json { render json: {msg: "failure"} }
      end
    end
  end

  private

  def message_params
    params.require(:message).permit(:creator_id, :message, :read, :receiver_id)
  end
end
