package cobraauth

import (
	"fmt"
	"time"

	"github.com/cerberauth/x/authx"
	"github.com/spf13/cobra"
)

// NewAuthCommand returns a cobra.Command subtree for auth management.
// Wire it into the root command: rootCmd.AddCommand(cobraauth.NewAuthCommand(a))
func NewAuthCommand(a *authx.Authenticator) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "auth",
		Short: "Manage cerberauth authentication",
	}

	var deviceCode bool
	loginCmd := &cobra.Command{
		Use:   "login",
		Short: "Log in to cerberauth (opens browser)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if deviceCode {
				return a.LoginDeviceCode(cmd.Context())
			}
			return a.LoginAuthCode(cmd.Context())
		},
	}
	loginCmd.Flags().BoolVar(&deviceCode, "device-code", false, "use device code flow for headless environments")

	logoutCmd := &cobra.Command{
		Use:   "logout",
		Short: "Clear stored credentials",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := a.Logout(cmd.Context()); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "Logged out.")
			return nil
		},
	}

	statusCmd := &cobra.Command{
		Use:   "status",
		Short: "Show authentication status",
		RunE: func(cmd *cobra.Command, args []string) error {
			info, err := a.Status(cmd.Context())
			if err != nil {
				fmt.Fprintln(cmd.OutOrStdout(), "Not logged in.")
				return nil
			}
			if info.Expiry.IsZero() {
				fmt.Fprintln(cmd.OutOrStdout(), "Logged in.")
			} else {
				fmt.Fprintf(cmd.OutOrStdout(), "Logged in. Token expires: %s\n",
					info.Expiry.Format(time.RFC3339))
			}
			return nil
		},
	}

	cmd.AddCommand(loginCmd, logoutCmd, statusCmd)
	return cmd
}
