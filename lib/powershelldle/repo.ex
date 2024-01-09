defmodule PowerShelldle.Repo do
  use Ecto.Repo,
    otp_app: :powershelldle,
    adapter: Ecto.Adapters.Postgres
end
