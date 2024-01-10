defmodule PowerShelldleWeb.Index do
  use PowerShelldleWeb, :live_view
  import Phoenix.Component

  require Logger

  @spec render(map) :: Phoenix.LiveView.Rendered.t()
  def render(assigns) do
    ~H"""
    <h1>Daily PowerShelldle</h1>
    <.form :let={f} for={@changeset} phx-submit="submit_guess">
      <h2 :if={@error} class="error"><%= @error %></h2>
      <h2 :if={@success}><%= @success %></h2>
      <div class="flex flex-row">
        <div :for={answer_char <- Ecto.Changeset.get_field(@changeset, :answer)} class="mr-1">
          <%= answer_char %>
        </div>
      </div>
      <ul>
        <li :for={hint <- Ecto.Changeset.get_field(@changeset, :hints)}>
          <div :if={not is_nil(hint)}>
            <p>Hint:</p>
            <p><%= hint %></p>
          </div>
        </li>
      </ul>
      <.input type="text" field={f[:guess]} disabled={!!@error || !!@success} />
      <button
        type="submit"
        disabled={!!@error || !!@success}
        class="text-center inline-block rounded select-none mt-3 p-2 disabled:pointer-events-none bg-blue-300 hover:bg-blue-500 text-white"
      >
        Submit guess
      </button>
    </.form>
    """
  end

  @spec mount(map, map, Phoenix.LiveView.Socket.t()) :: {:ok, Phoenix.LiveView.Socket.t()}
  def mount(_params, _session, socket) do
    command = %{
      name: "Get-ChildItem",
      description: "Gets the files and folders in a file system drive.",
      params:
        "[[-Filter] <String>] [-Attributes {ReadOnly | Hidden | System | Directory | Archive | Device |Normal | Temporary | SparseFile | ReparsePoint | Compressed | Offline | NotContentIndexed | Encrypted |IntegrityStream | NoScrubData}] [-Depth <UInt32>] [-Directory] [-Exclude <String[]>] [-File] [-Force] [-Hidden][-Include <String[]>] -LiteralPath* <String[]> [-Name] [-ReadOnly] [-Recurse] [-System] [-UseTransaction][<CommonParameters>]"
    }

    changeset = Puzzle.changeset(%Puzzle{}, %{command: command, hints: []})

    {:ok, assign(socket, changeset: changeset, command: command, error: nil, success: nil)}
  end

  @spec handle_event(String.t(), map, Phoenix.LiveView.Socket.t()) ::
          {:noreply, Phoenix.LiveView.Socket.t()}
  def handle_event(
        "submit_guess",
        %{"puzzle" => %{"guess" => guess} = params},
        %{assigns: %{command: command, changeset: changeset}} = socket
      ) do
    guesses = Ecto.Changeset.get_field(changeset, :guesses)

    case {correct_answer?(guess, command.name), length(guesses)} do
      {true, _guesses} ->
        {:noreply, assign(socket, success: "YOU WON!!!")}

      {_invalid, 4} ->
        {:noreply, assign(socket, error: "YOU LOSE SUCKER!!!")}

      _still_playing ->
        params = Map.put(params, "command", command)

        {:noreply, assign(socket, changeset: Puzzle.changeset(changeset, params))}
    end
  end

  defp correct_answer?(guess, command_name),
    do: String.downcase(guess) == String.downcase(command_name)
end
