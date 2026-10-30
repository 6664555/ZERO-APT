"""
Use action_sharpen.py to rewrite and refine the actions in action_library, ensuring each action
matches the feasibility definition, can execute directly in the post-exploitation phase, and
highlights attack intent and behavior.
Uses its functions.
"""

def main():
    """
    Call the functions from action_sharpen.py to rewrite and refine the action library
    (API key read from the DEEPSEEK_API_KEY env var).
    """
    import os
    # API key read from the environment
    api_key = os.environ.get("DEEPSEEK_API_KEY") or ""

    # import the action_sharpen module and call sharpen_actions
    try:
        import action_sharpen
        print("Starting action-library rewrite and refinement...")
        action_sharpen.sharpen_actions(api_key)
        print("Action-library rewrite complete!")
    except ImportError as e:
        print(f"Error: could not import the action_sharpen module: {e}")
    except Exception as e:
        print(f"Error: exception during action-library rewrite: {e}")

if __name__ == "__main__":
    main()
