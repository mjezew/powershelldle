defmodule PowerShelldleWeb.PageControllerTest do
  use PowerShelldleWeb.ConnCase

  @command %{
    description: "Starts one or more stopped services.",
    name: "Start-Service",
    params:
      "[-Confirm] -DisplayName* <String[]> [-Exclude <String[]>] [-Include <String[]>] [-PassThru] [-WhatIf][<CommonParameters>]"
  }

  setup do
    CommandsMock
    |> stub(:get_by_id, fn _id -> @command end)

    :ok
  end

  test "GET /", %{conn: conn} do
    conn = get(conn, ~p"/")
    assert html_response(conn, 200) =~ "PowerShelldle"
  end
end
