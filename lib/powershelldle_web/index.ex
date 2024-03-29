defmodule PowerShelldleWeb.Index do
  use PowerShelldleWeb, :live_view
  import Phoenix.Component

  require Logger

  defp commands, do: Application.get_env(:powershelldle, PowerShelldle.Behaviour.Commands)

  @spec render(map) :: Phoenix.LiveView.Rendered.t()
  def render(assigns) do
    ~H"""
    <div :if={@help_open?}>
      <div class="relative z-10" aria-labelledby="modal-title" role="dialog" aria-modal="true">
        <!-- Background backdrop -->
        <div class="fixed inset-0 bg-zinc-700 bg-opacity-75 transition-opacity"></div>

        <div class="fixed inset-0 z-10 w-screen overflow-y-auto">
          <div class="flex min-h-full items-end justify-center p-4 text-center sm:items-center sm:p-0">
            <!--
        Modal panel, show/hide based on modal state.

        Entering: "ease-out duration-300"
          From: "opacity-0 translate-y-4 sm:translate-y-0 sm:scale-95"
          To: "opacity-100 translate-y-0 sm:scale-100"
        Leaving: "ease-in duration-200"
          From: "opacity-100 translate-y-0 sm:scale-100"
          To: "opacity-0 translate-y-4 sm:translate-y-0 sm:scale-95"
      -->
            <div class="relative transform overflow-hidden rounded-lg bg-zinc-900 text-left shadow-xl transition-all sm:my-8 sm:w-full sm:max-w-lg">
              <div class="bg-zinc-900 px-4 pb-4 pt-5 sm:p-6 sm:pb-4">
                <div class="sm:flex sm:items-start">
                  <div class="mt-3 text-center sm:ml-4 sm:mt-0 sm:text-left">
                    <div class="flex flex-row justify-between items-center">
                      <h3 class="text-base font-semibold leading-6 text-zinc-300" id="modal-title">
                        How to play Powershelldle
                      </h3>
                      <button phx-click="help_close" id="close-button">
                        <span class="material-symbols-outlined">
                          close
                        </span>
                      </button>
                    </div>
                    <div class="mt-2">
                      <p class="text-sm text-gray-500">
                        Guess the PowerShell cmdlet! You have 5 attempts to guess the correct cmdlet.
                        After each guess, you'll receive various hints to help you get the answer.
                        There will be a new puzzle every day! Can you decipher the cmdlet and master PowerShell vocabulary?
                      </p>
                      <h4 class="text-base font-semibold text-zinc-400 text-sm mt-8">Hint info:</h4>
                      <ol class="list-decimal pl-8 mt-2 space-y-2">
                        <li class="text-sm text-gray-500">
                          The first hint will be the verb of the commandlet. For example if the answer is "<%= commands().get_example().name %>",
                          the hint will be "<%= String.split(commands().get_example().name, "-")
                          |> List.first() %>" and will fill in the puzzle at the top.
                        </li>
                        <li class="text-sm text-gray-500">
                          The second hint will be the first letter of the second part of the commandlet. For example if the answer is "Write-Host",
                          the hint will be "<%= String.split(commands().get_example().name, "-")
                          |> List.last()
                          |> String.codepoints()
                          |> List.first() %>" and will fill in the puzzle at the top.
                        </li>
                        <li class="text-sm text-gray-500">
                          The third hint will be the syntax parameters for the commandlet. For example if the answer is "Write-Host",
                          the hint will be:
                          "<code class="mt-8">
                            <%= commands().get_example().params %>
                          </code>"
                        </li>
                        <li class="text-sm text-gray-500">
                          The fourth and final hint will be the description of the commandlet. For example if the answer is "Write-Host",
                          the hint will be "<%= commands().get_example().description %>"
                        </li>
                      </ol>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
    <.form :let={f} for={@changeset} id="powerform" phx-submit="submit_guess" phx-hook="LocalStorage">
      <div
        id="answer"
        class={"flex flex-row justify-center items-center border border-zinc-700 rounded p-4 relative mb-4 w-full h-16 ping-chillin-before #{if @flashing?, do: "ping-chillin", else: ""}"}
      >
        <div
          :for={answer_char <- Ecto.Changeset.get_field(@changeset, :answer)}
          id="answer-char"
          class="mr-0.5 md:text-2xl"
        >
          <%= answer_char %>
        </div>
      </div>
      <div><.ps_label />Write-Host "Remaining guesses: $i" -ForegroundColor DarkBlue</div>
      <p id="remaining-guesses" class="text-[#3672c0] mb-4">
        Remaining guesses: <%= 5 - (Ecto.Changeset.get_field(@changeset, :guesses, 5) |> length) %>
      </p>

      <div :if={not (Ecto.Changeset.get_field(@changeset, :hints) |> List.first() |> is_nil())}>
        <div class="flex flex-row flex-wrap items-center">
          <.ps_label />
          <p class="whitespace-nowrap pr-3">Get-Help</p>

          <div :for={answer_char <- Ecto.Changeset.get_field(@changeset, :answer)}>
            <%= answer_char %>
          </div>
        </div>
        <ul>
          <li>
            <div
              :if={not (Ecto.Changeset.get_field(@changeset, :hints) |> Enum.at(1) |> is_nil())}
              id="synopsis"
              class="mt-2"
            >
              <p class="font-bold text-zinc-300">SYNOPSIS</p>
              <p class="mb-6 ml-10 typewriter">
                <%= Ecto.Changeset.get_field(@changeset, :hints) |> Enum.at(1) %>
              </p>
            </div>
          </li>
          <li>
            <div id="syntax" class="mt-2">
              <p class="font-bold text-zinc-300">SYNTAX</p>
              <p class="mb-6 ml-10 typewriter">
                <%= Ecto.Changeset.get_field(@changeset, :hints) |> List.first() %>
              </p>
            </div>
          </li>
        </ul>
      </div>
      <div :if={!!@error || @success} class="mt-4">
        <div :if={@error}><.ps_label />Write-Host "<%= @error %>" -ForegroundColor Red</div>
        <p :if={@error} class="text-red-700 mb-6"><%= @error %></p>
        <div :if={@success}><.ps_label />Write-Host "<%= @success %>" -ForegroundColor Green</div>
        <p :if={@success} class="text-green-700 mb-6"><%= @success %></p>
        <div><.ps_label />Write-Host "Come back tomorrow for a new puzzle!"</div>
        <p>Come back tomorrow for a new puzzle!</p>
      </div>
      <div :if={!@error and !@success}>
        <.ps_label />Read-Host -OutVariable guess
        <div class="flex flex-row items-center">
          <div class="relative flex grow">
            <div class={[
              "absolute z-0 flex flex-row border border-transparent text-zinc-400 tracking-[.125em] p-0 -bottom-1"
            ]}>
              <div
                :for={answer_char <- Ecto.Changeset.get_field(@changeset, :answer)}
                id="answer-char"
                class={(answer_char == "-" && "relative bottom-1") || ""}
              >
                <%= (answer_char == "-" && "-") || "_" %>
              </div>
            </div>
            <.input
              type="text"
              maxlength={length(Ecto.Changeset.get_field(@changeset, :answer))}
              id="guess"
              field={f[:guess]}
              disabled={!!@error || !!@success}
            />
          </div>
        </div>
      </div>
    </.form>
    """
  end

  @spec mount(map, map, Phoenix.LiveView.Socket.t()) :: {:ok, Phoenix.LiveView.Socket.t()}
  def mount(_params, _session, socket) do
    today = Timex.day(Timex.now())
    command = commands().get_by_id(today)

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
       flashing?: false,
       help_open?: false,
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
            guesses |> Stream.concat(Stream.repeatedly(fn -> guess end)) |> Enum.take(4)

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
          if length(guesses) in [0, 1] do
            Process.send_after(self(), :stop_flashing, 300)

            assign(socket,
              flashing?: true
            )
          else
            socket
          end
          |> assign(changeset: changeset)
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
              command: commands().get_by_id(id),
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

  def handle_event("restorePuzzle", _puzzle_data, socket) do
    Logger.debug("No LiveView SessionStorage state to restore")
    {:noreply, socket}
  end

  def handle_event("help_open", _, socket) do
    Logger.debug("open")
    socket = assign(socket, help_open?: true)

    {:noreply, socket}
  end

  def handle_event("help_close", _, socket) do
    Logger.debug("close")
    socket = assign(socket, help_open?: false)
    {:noreply, socket}
  end

  def handle_info(:stop_flashing, socket) do
    socket = assign(socket, flashing?: false)

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
