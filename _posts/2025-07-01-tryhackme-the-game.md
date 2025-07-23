---
title: TryHackMe - The Game
categories: [CTF Challenges]
tags: [TryHackMe, Game Hacking, Cheat Engine, Memory Editing]
date: 2025-07-23
---

Description of TryHackMe [The Game](https://tryhackme.com/room/thegame) (Premium room)

> Practice your Game Hacking skills.
> Difficulty: easy
> Estimated time: 10 min

![img-description](/assets/img/thm-the-game/thm-the-game-banner.png)

## Challenge Overview

In this challenge, we are provided with a downloadable archive containing the files for a game called Tetrix (or Tetrim), built with the Godot game engine. The objective is simple: achieve a score higher than 999,999 to reveal the flag.

## Initial Analysis

After extracting the provided files, I located the game executable and launched it. The game presents itself as a classic Tetris clone, with standard controls and scoring mechanics.

![img-description](/assets/img/thm-the-game/thm-the-game-gameplay.png)

Reaching a score of 999,999 through normal gameplay would be extremely time-consuming. Instead, I decided to use Cheat Engine to manipulate the game's memory and set the score directly.

## Attaching Cheat Engine

I opened Cheat Engine and attached it to the running Tetrix process. This allows us to scan and modify the values stored in the game's memory in real time.

![img-description](/assets/img/thm-the-game/thm-the-game-cheatengine-attach.png)

## Locating the Score in Memory

To find the memory address holding the score, I first increased my score in the game to 100. I then performed an initial scan in Cheat Engine for the value 100.

![img-description](/assets/img/thm-the-game/thm-the-game-cheatengine-first-scan.png)

Next, I increased my score again to 200 and performed a 'Next Scan' for the new value. This narrowed down the results to a single address, which likely represented the score variable.

![img-description](/assets/img/thm-the-game/thm-the-game-cheatengine-next-scan.png)

## Modifying the Score

With the correct address identified, I changed the value at that address to 1,000,000.

![img-description](/assets/img/thm-the-game/thm-the-game-cheatengine-values.png)

Returning to the game, I performed one more scoring action to trigger the UI update. Instantly, the score reflected the new value, and the flag was displayed on the screen.

![img-description](/assets/img/thm-the-game/thm-the-game-flag.gif)
