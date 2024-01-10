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

  defmodule PowerShelldle do
    use Ecto.Schema
    import Ecto.Changeset

    embedded_schema do
      field :hints, {:array, :string}
      field :answer, {:array, :string}
      field :guess, :string
      field :guesses, {:array, :string}
    end

    @type t :: %__MODULE__{
            hints: [String.t()],
            answer: [String.t()],
            guess: String.t() | nil,
            guesses: [String.t()]
          }

    @spec changeset(%__MODULE__{}, map()) :: Ecto.Changeset.t(t())
    def changeset(user, params) do
      command = get_command(params)

      user
      |> cast(params, [:guess, :guesses, :hints, :answer])
      |> handle_guesses()
      |> derive_hints(command)
      |> derive_answer(command)
    end

    defp handle_guesses(changeset) do
      guess = get_field(changeset, :guess) || ""
      guesses = update_guesses(get_field(changeset, :guesses), guess)

      put_change(changeset, :guesses, guesses)
    end

    defp derive_hints(changeset, command) do
      step = get_field(changeset, :guesses) |> length()
      hints = get_field(changeset, :hints)

      hints =
        case step do
          step when step in [0, 1, 2] -> []
          3 -> hints ++ [command.params]
          4 -> hints ++ [command.description]
          5 -> hints ++ ["u lose sucker"]
        end

      put_change(changeset, :hints, hints)
    end

    defp derive_answer(changeset, command) do
      step = get_field(changeset, :guesses) |> length()

      answer =
        case step do
          0 -> init_answer(command.name)
          1 -> get_verb(command.name)
          2 -> get_verb_and_first_letter(command.name)
          _other_step -> get_field(changeset, :answer)
        end

      put_change(changeset, :answer, answer)
    end

    defp init_answer(command_name) do
      Enum.map(String.codepoints(command_name), fn graph ->
        if graph == "-", do: "-", else: "_"
      end)
    end

    defp update_guesses(nil, ""), do: []
    defp update_guesses(nil, guess), do: [guess]
    defp update_guesses(guesses, guess), do: [guess | guesses]

    defp get_verb(command_name) do
      [verb, noun] = String.split(command_name, "-")
      noun = String.codepoints(noun)
      (verb |> String.codepoints()) ++ ["-"] ++ Enum.map(noun, fn _char -> "_" end)
    end

    defp get_verb_and_first_letter(command_name) do
      [verb, noun] = String.split(command_name, "-")
      first_letter = String.at(noun, 0)
      noun = String.codepoints(noun)

      (verb |> String.codepoints()) ++
        ["-"] ++ [first_letter] ++ (noun |> Enum.drop(1) |> Enum.map(fn _c -> "_" end))
    end

    defp get_command(%{"command" => command}), do: command
    defp get_command(%{command: command}), do: command
  end

  @spec mount(map, map, Phoenix.LiveView.Socket.t()) :: {:ok, Phoenix.LiveView.Socket.t()}
  def mount(_params, _session, socket) do
    command = %{
      name: "Get-ChildItem",
      description: "Gets the files and folders in a file system drive.",
      params:
        "[[-Filter] <String>] [-Attributes {ReadOnly | Hidden | System | Directory | Archive | Device |Normal | Temporary | SparseFile | ReparsePoint | Compressed | Offline | NotContentIndexed | Encrypted |IntegrityStream | NoScrubData}] [-Depth <UInt32>] [-Directory] [-Exclude <String[]>] [-File] [-Force] [-Hidden][-Include <String[]>] -LiteralPath* <String[]> [-Name] [-ReadOnly] [-Recurse] [-System] [-UseTransaction][<CommonParameters>]"
    }

    changeset = PowerShelldle.changeset(%PowerShelldle{}, %{command: command, hints: []})

    {:ok, assign(socket, changeset: changeset, command: command, error: nil, success: nil)}
  end

  @spec handle_event(String.t(), map, Phoenix.LiveView.Socket.t()) ::
          {:noreply, Phoenix.LiveView.Socket.t()}
  def handle_event(
        "submit_guess",
        %{"power_shelldle" => %{"guess" => guess} = params},
        %{assigns: %{command: command, changeset: changeset}} = socket
      ) do
    guesses = Ecto.Changeset.get_field(changeset, :guesses)

    case {correct_answer?(guess, command.name), length(guesses)} do
      {true, _guesses} ->
        {:noreply, assign(socket, success: "YOU WON!!!")}

      {_invalid, 4} ->
        {:noreply, assign(socket, error: "YOU LOSE!")}

      _still_playing ->
        params = Map.put(params, "command", command)

        {:noreply, assign(socket, changeset: PowerShelldle.changeset(changeset, params))}
    end
  end

  defp correct_answer?(guess, command_name),
    do: String.downcase(guess) == String.downcase(command_name)
end
