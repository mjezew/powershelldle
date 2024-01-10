defmodule PowerShelldle.Application do
  # See https://hexdocs.pm/elixir/Application.html
  # for more information on OTP Applications
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    children = [
      # Start the Telemetry supervisor
      PowerShelldleWeb.Telemetry,
      # Start the Ecto repository
      # PowerShelldle.Repo,
      # Start the PubSub system
      {Phoenix.PubSub, name: PowerShelldle.PubSub},
      # Start Finch
      {Finch, name: PowerShelldle.Finch},
      # Start the Endpoint (http/https)
      PowerShelldleWeb.Endpoint
      # Start a worker by calling: PowerShelldle.Worker.start_link(arg)
      # {PowerShelldle.Worker, arg}
    ]

    # See https://hexdocs.pm/elixir/Supervisor.html
    # for other strategies and supported options
    opts = [strategy: :one_for_one, name: PowerShelldle.Supervisor]
    Supervisor.start_link(children, opts)
  end

  # Tell Phoenix to update the endpoint configuration
  # whenever the application is updated.
  @impl true
  def config_change(changed, _new, removed) do
    PowerShelldleWeb.Endpoint.config_change(changed, removed)
    :ok
  end
end
