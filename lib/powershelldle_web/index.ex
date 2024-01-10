defmodule PowerShelldleWeb.Index do
  use PowerShelldleWeb, :live_view
  import Phoenix.Component

  alias PowerShelldle.Commands

  require Logger

  @spec render(map) :: Phoenix.LiveView.Rendered.t()
  def render(assigns) do
    ~H"""
    <.form :let={f} for={@changeset} id="powerform" phx-submit="submit_guess" phx-hook="LocalStorage">
      <div class="flex flex-row">
        <div :for={answer_char <- Ecto.Changeset.get_field(@changeset, :answer)} class="mr-1">
          <%= answer_char %>
        </div>
      </div>
      <div :if={not (Ecto.Changeset.get_field(@changeset, :hints) |> List.first() |> is_nil())}>
        <ul>
          <li>
            <div class="mt-2">
              <p class="font-bold text-zinc-300">Parameters:</p>
              <div class="bg-zinc-600 rounded p-2">
                <code>
                  <%= Ecto.Changeset.get_field(@changeset, :hints) |> List.first() %>
                </code>
              </div>
            </div>
          </li>
          <li>
            <div
              :if={not (Ecto.Changeset.get_field(@changeset, :hints) |> Enum.at(1) |> is_nil())}
              class="mt-2"
            >
              <p class="font-bold text-zinc-300">Description:</p>
              <p><%= Ecto.Changeset.get_field(@changeset, :hints) |> Enum.at(1) %></p>
            </div>
          </li>
        </ul>
      </div>
      <div :if={!!@error || @success} class="mt-4">
        <p :if={@error} class="text-red-700"><%= @error %></p>
        <p :if={@success} class="text-green-700"><%= @success %></p>
        <p>Come back tomorrow for a new puzzle!</p>
      </div>
      <div :if={!@error and !@success}>
        <.input type="text" field={f[:guess]} disabled={!!@error || !!@success} class="bg-zinc-200" />
        <button
          type="submit"
          disabled={!!@error || !!@success}
          class="text-center inline-block rounded select-none mt-3 p-2 disabled:pointer-events-none bg-blue-900 hover:bg-blue-950 text-white"
        >
          Submit guess
        </button>
      </div>
    </.form>
    """
  end

  @spec mount(map, map, Phoenix.LiveView.Socket.t()) :: {:ok, Phoenix.LiveView.Socket.t()}
  def mount(_params, _session, socket) do
    today = Timex.day(Timex.now())
    command = Commands.get_by_id(today)

    changeset = Puzzle.changeset(%Puzzle{}, %{command: command, hints: []})

    # Only try to talk to the client when the websocket
    # is setup. Not on the initial "static" render.
    new_socket =
      if connected?(socket) do
        storage_key = "powershelldle"

        socket
        |> assign(:storage_key, storage_key)
        # request the browser to restore any state it has for this key.
        |> push_event("restore", %{key: storage_key, event: "restorePuzzle"})
      else
        socket
      end

    {:ok,
     assign(new_socket,
       changeset: changeset,
       command: command,
       error: nil,
       success: nil,
       id: today
     )}
  end

  @spec handle_event(String.t(), map, Phoenix.LiveView.Socket.t()) ::
          {:noreply, Phoenix.LiveView.Socket.t()}
  def handle_event(
        "submit_guess",
        %{"puzzle" => %{"guess" => guess} = params},
        %{assigns: %{command: command, changeset: changeset}} = socket
      ) do
    guesses = Ecto.Changeset.get_field(changeset, :guesses)

    params = Map.put(params, "command", command)
    changeset = Puzzle.changeset(changeset, params)

    socket =
      case {Puzzle.correct_answer?(guess, command.name), length(guesses)} do
        {true, _guesses} ->
          full_guesses =
            guesses |> Stream.concat(Stream.repeatedly(fn -> guess end)) |> Enum.take(5)

          params = Map.put(params, "guesses", full_guesses) |> Map.delete("guess")
          changeset = Puzzle.changeset(changeset, params)

          assign(socket,
            success: "YOU WON!!!",
            changeset: changeset
          )

        {_invalid, 4} ->
          assign(socket,
            error: "YOU LOSE SUCKER!!!",
            changeset: changeset
          )

        _still_playing ->
          assign(socket, changeset: changeset)
      end
      |> store_state()

    {:noreply, socket}
  end

  # Pushed from JS hook. Server requests it to send up any
  # stored settings for the key.
  def handle_event("restorePuzzle", puzzle_data, socket) when is_binary(puzzle_data) do
    socket =
      case restore_from_stored(puzzle_data, socket) do
        {:ok, nil} ->
          # do nothing with the previous state
          socket

        {:ok, %{id: id, guesses: guesses, error: error, success: success}} ->
          changeset =
            Puzzle.changeset(%Puzzle{}, %{
              command: Commands.get_by_id(id),
              guesses: guesses,
              hints: []
            })

          assign(socket, changeset: changeset, error: error, success: success)

        {:error, _reason} ->
          # We don't continue checking. Display error.
          # Clear the token so it doesn't keep showing an error.
          socket
          |> clear_browser_storage()
      end

    {:noreply, socket}
  end

  def handle_event("restorePuzzle", _token_data, socket) do
    # No expected token data received from the client
    Logger.debug("No LiveView SessionStorage state to restore")
    {:noreply, socket}
  end

  defp restore_from_stored(puzzle_data, socket) do
    today = socket.assigns.id

    case Jason.decode(puzzle_data) do
      {:ok, %{"id" => id, "guesses" => guesses, "success" => success, "error" => error}} ->
        if id == today do
          {:ok, %{guesses: guesses, id: id, success: success, error: error}}
        else
          {:ok, nil}
        end

      {:ok, _} ->
        {:ok, nil}

      {:error, reason} ->
        {:error, "Unable to decode stored state: #{inspect(reason)}"}
    end
  end

  # Push a websocket event down to the browser's JS hook.
  # Clear any settings for the current my_storage_key.
  defp clear_browser_storage(socket) do
    push_event(socket, "clear", %{key: socket.assigns.storage_key})
  end

  defp store_state(socket) do
    id = socket.assigns.id
    success = socket.assigns.success
    error = socket.assigns.error
    guesses = Ecto.Changeset.get_field(socket.assigns.changeset, :guesses)

    socket
    |> push_event(
      "store",
      %{
        key: socket.assigns.storage_key,
        data: Jason.encode!(%{id: id, guesses: guesses, error: error, success: success})
      }
    )
  end
end
