class UsersController < ApplicationController
  def index
    @users = User.where("name = '#{params[:name]}'")
    system("convert #{params[:file]} out.png")
    redirect_to params[:next]
  end
end
