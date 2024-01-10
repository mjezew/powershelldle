defmodule Puzzle do
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

  def correct_answer?(nil, _command_name), do: false

  def correct_answer?(guess, command_name),
    do: String.downcase(guess) == String.downcase(command_name)

  defp handle_guesses(changeset) do
    guess = get_field(changeset, :guess)
    guesses = get_field(changeset, :guesses)

    cond do
      is_nil(guess) and not is_nil(guesses) and not Enum.empty?(guesses) ->
        changeset

      is_nil(guess) ->
        put_change(changeset, :guesses, [])

      true ->
        guesses = update_guesses(get_field(changeset, :guesses), guess)
        put_change(changeset, :guesses, guesses)
    end
  end

  defp derive_hints(changeset, command) do
    step = get_field(changeset, :guesses) |> length()

    hints =
      case step do
        step when step in [0, 1, 2] -> []
        3 -> [command.params]
        _ -> [command.params, command.description]
      end

    put_change(changeset, :hints, hints)
  end

  defp derive_answer(changeset, command) do
    guesses = get_field(changeset, :guesses)
    step = length(guesses) |> IO.inspect()

    guess = List.first(guesses)

    answer =
      if correct_answer?(guess, command.name) do
        String.codepoints(command.name)
      else
        case step do
          0 -> init_answer(command.name)
          1 -> get_verb(command.name)
          5 -> String.codepoints(command.name)
          _ -> get_verb_and_first_letter(command.name)
        end
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
