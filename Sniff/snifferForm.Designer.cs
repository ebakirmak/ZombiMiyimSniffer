namespace Sniffer
{
    partial class snifferForm
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                if (components != null)
                {
                    components.Dispose();
                }
                if (mainSocket != null)
                {
                    mainSocket.Dispose();
                    mainSocket = null;
                }
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            this.components = new System.ComponentModel.Container();
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(snifferForm));
            this.treeView = new System.Windows.Forms.TreeView();
            this.btnStart = new System.Windows.Forms.Button();
            this.cmbInterfaces = new System.Windows.Forms.ComboBox();
            this.atkList = new System.Windows.Forms.ListBox();
            this.notifyIcon1 = new System.Windows.Forms.NotifyIcon(this.components);
            this.SuspendLayout();
            // 
            // treeView
            // 
            this.treeView.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom) 
            | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.treeView.Location = new System.Drawing.Point(12, 12);
            this.treeView.Name = "treeView";
            this.treeView.Size = new System.Drawing.Size(288, 213);
            this.treeView.TabIndex = 0;
            // 
            // btnStart
            // 
            this.btnStart.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left)));
            this.btnStart.Location = new System.Drawing.Point(12, 232);
            this.btnStart.Name = "btnStart";
            this.btnStart.Size = new System.Drawing.Size(91, 33);
            this.btnStart.TabIndex = 1;
            this.btnStart.Text = "&Start";
            this.btnStart.UseVisualStyleBackColor = true;
            this.btnStart.Click += new System.EventHandler(this.btnStart_Click);
            // 
            // cmbInterfaces
            // 
            this.cmbInterfaces.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.cmbInterfaces.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.cmbInterfaces.FormattingEnabled = true;
            this.cmbInterfaces.Location = new System.Drawing.Point(128, 239);
            this.cmbInterfaces.Name = "cmbInterfaces";
            this.cmbInterfaces.Size = new System.Drawing.Size(172, 21);
            this.cmbInterfaces.TabIndex = 2;
            // 
            // atkList
            // 
            this.atkList.Dock = System.Windows.Forms.DockStyle.Right;
            this.atkList.FormattingEnabled = true;
            this.atkList.Location = new System.Drawing.Point(306, 0);
            this.atkList.Name = "atkList";
            this.atkList.Size = new System.Drawing.Size(312, 271);
            this.atkList.TabIndex = 3;
            // 
            // notifyIcon1
            // 
            this.notifyIcon1.Icon = ((System.Drawing.Icon)(resources.GetObject("notifyIcon1.Icon")));
            this.notifyIcon1.Text = "notifyIcon1";
            this.notifyIcon1.Visible = true;
            // 
            // snifferForm
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(618, 271);
            this.Controls.Add(this.atkList);
            this.Controls.Add(this.cmbInterfaces);
            this.Controls.Add(this.btnStart);
            this.Controls.Add(this.treeView);
            this.Name = "snifferForm";
            this.Text = "Sniffer";
            this.FormClosing += new System.Windows.Forms.FormClosingEventHandler(this.SnifferForm_FormClosing);
            this.Load += new System.EventHandler(this.SnifferForm_Load);
            this.ResumeLayout(false);

        }

        #endregion

        private System.Windows.Forms.TreeView treeView;
        private System.Windows.Forms.Button btnStart;
        private System.Windows.Forms.ComboBox cmbInterfaces;
        private System.Windows.Forms.ListBox atkList;
        private System.Windows.Forms.NotifyIcon notifyIcon1;
    }
}

