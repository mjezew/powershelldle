defmodule PowerShelldleWeb.IndexTest do
  use PowerShelldleWeb.ConnCase

  import Phoenix.LiveViewTest

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

  test "success on first guess", %{conn: conn} do
    conn = get(conn, ~p"/")
    {:ok, live, _html} = live(conn)

    assert live |> element("p#remaining-guesses", "Remaining guesses: 5") |> has_element?()

    assert live
           |> element("form#powerform")
           |> render_submit(%{"puzzle" => %{"guess" => @command.name}})

    assert live |> element("p#remaining-guesses", "Remaining guesses: 0") |> has_element?()
    assert live |> element("div", "YOU WON!!!") |> has_element?()
  end

  test "success on last guess", %{conn: conn} do
    conn = get(conn, ~p"/")
    {:ok, live, _html} = live(conn)

    assert live |> element("p#remaining-guesses", "Remaining guesses: 5") |> has_element?()

    Enum.each(4..0, fn remaining_guess ->
      assert live
             |> element("form#powerform")
             |> render_submit(%{"puzzle" => %{"guess" => "Get-Packages"}})

      assert live
             |> element("p#remaining-guesses", "Remaining guesses: #{remaining_guess}")
             |> has_element?()

      if remaining_guess == 1 do
        assert live
               |> element("#syntax")
               |> has_element?()
      end

      if remaining_guess == 0 do
        assert live
               |> element("#synopsis", @command.description)
               |> has_element?()
      end
    end)

    assert live
           |> element("form#powerform")
           |> render_submit(%{"puzzle" => %{"guess" => @command.name}})

    assert live |> element("p#remaining-guesses", "Remaining guesses: 0") |> has_element?()
    assert live |> element("div", "YOU WON!!!") |> has_element?()
  end

  test "game failure", %{conn: conn} do
    conn = get(conn, ~p"/")
    {:ok, live, _html} = live(conn)

    assert live |> element("p#remaining-guesses", "Remaining guesses: 5") |> has_element?()

    Enum.each(4..0, fn remaining_guesses ->
      assert live
             |> element("form#powerform")
             |> render_submit(%{"puzzle" => %{"guess" => "Get-Packages"}})

      assert live
             |> element("p#remaining-guesses", "Remaining guesses: #{remaining_guesses}")
             |> has_element?()
    end)

    # final guess
    assert live
           |> element("form#powerform")
           |> render_submit(%{"puzzle" => %{"guess" => "Get-Packages"}})

    assert live |> element("div", "YOU LOSE SUCKER!!!") |> has_element?()
  end

  test "help modal opens", %{conn: conn} do
    conn = get(conn, ~p"/")
    {:ok, live, _html} = live(conn)

    assert live |> element("p#remaining-guesses", "Remaining guesses: 5") |> has_element?()

    live
    |> element("button#help-button")
    |> render_click()

    assert live |> element("h3", "How to play Powershelldle") |> has_element?()
  end

  test "help modal closes", %{conn: conn} do
    conn = get(conn, ~p"/")
    {:ok, live, _html} = live(conn)

    assert live |> element("p#remaining-guesses", "Remaining guesses: 5") |> has_element?()

    live
    |> element("button#help-button")
    |> render_click()

    assert live |> element("h3", "How to play Powershelldle") |> has_element?()

    live
    |> element("button#close-button")
    |> render_click()

    refute live |> element("h3", "How to play Powershelldle") |> has_element?()
  end

  def command_answer(0) do
    Enum.reduce(String.codepoints(@command.name), "", fn graph, acc ->
      new_char = if graph == "-", do: "-", else: "_"
      acc <> new_char
    end)
  end

  def command_answer(1) do
    [verb, noun] = String.split(@command.name, "-")
    noun = String.codepoints(noun)
    (verb |> String.codepoints()) ++ ["-"] ++ Enum.map(noun, fn _char -> "_" end)
  end

  def command_answer(2) do
    [verb, noun] = String.split(@command.name, "-")
    first_letter = String.at(noun, 0)
    noun = String.codepoints(noun)

    (verb |> String.codepoints()) ++
      ["-"] ++ [first_letter] ++ (noun |> Enum.drop(1) |> Enum.map(fn _c -> "_" end))
  end
end
