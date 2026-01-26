import csv
import argparse
import os
import sys


def add_platform_column(input_file, output_file, platform_value):
    """
    Reads a CSV, adds a 'platform' column with the specified value to every row,
    and writes to a new file.
    """
    try:
        with open(input_file, mode='r', newline='', encoding='utf-8-sig') as infile:
            reader = csv.DictReader(infile)

            if not reader.fieldnames:
                print(f"Error: {input_file} appears to be empty or invalid.")
                return

            # Add 'platform' to headers if not already present
            fieldnames = [f for f in reader.fieldnames if f != 'platform']
            fieldnames.append('platform')

            rows = list(reader)
            print(f"Read {len(rows)} rows from {input_file}...")

        with open(output_file, mode='w', newline='', encoding='utf-8') as outfile:
            writer = csv.DictWriter(outfile, fieldnames=fieldnames)
            writer.writeheader()

            for row in rows:
                # Add or overwrite the platform field
                row['platform'] = platform_value
                writer.writerow(row)

        print(f"Success! Created {output_file} with platform='{platform_value}'")

    except FileNotFoundError:
        print(f"Error: The file '{input_file}' was not found.")
    except Exception as e:
        print(f"An error occurred: {e}")


if __name__ == "__main__":
    # usage: python add_platform_to_csv.py input.csv output.csv windows
    parser = argparse.ArgumentParser(description="Add a 'platform' column to a CSV file.")
    parser.add_argument("input_file", help="Path to the source CSV file")
    parser.add_argument("output_file", help="Path where the modified CSV will be saved")
    parser.add_argument("platform", help="The value to put in the platform column (e.g., 'windows', 'linux')")

    args = parser.parse_args()

    add_platform_column(args.input_file, args.output_file, args.platform)