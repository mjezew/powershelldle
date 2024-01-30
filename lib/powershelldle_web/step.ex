defmodule Step do
  use Ecto.Schema
  import Ecto.Changeset

  embedded_schema do
    field :hint, :string
    field :answer, {:array, :string}
  end

  @type t :: %__MODULE__{
          hint: String.t(),
          answer: [String.t()]
        }

  @spec changeset(%__MODULE__{}, map(), integer, map) :: Ecto.Changeset.t(t())
  def changeset(step, params, step_number, command) do
    step
    |> cast(params, [:hint, :answer])
    |> derive_hint(command, step_number)
    |> derive_answer(command, step_number)
  end

  defp get_step_number(puzzle) do
    length(puzzle)
  end

  defp derive_hint(changeset, command, step) do
    hint =
      case step do
        step when step in [0, 1, 2] -> nil
        3 -> command.params
        4 -> command.description
      end

    put_change(changeset, :hint, hint)
  end

  defp derive_answer(changeset, command, step) do
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
