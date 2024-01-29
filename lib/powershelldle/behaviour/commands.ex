defmodule PowerShelldle.Behaviour.Commands do
  @callback get_by_id(integer) :: %{description: String.t(), name: String.t(), params: String.t()}
end
