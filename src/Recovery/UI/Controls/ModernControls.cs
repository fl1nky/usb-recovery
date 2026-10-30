using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Windows.Forms;

namespace UsbRecovery
{
    public sealed class SurfaceCard : Panel
    {
        public SurfaceCard(){DoubleBuffered=true;BackColor=Color.White;Padding=new Padding(18);Margin=new Padding(0,0,0,14);}
        protected override void OnPaint(PaintEventArgs e){base.OnPaint(e);using(var pen=new Pen(UiTheme.Border))e.Graphics.DrawRectangle(pen,0,0,Math.Max(0,Width-1),Math.Max(0,Height-1));}
    }
    public sealed class NavigationButton : Button
    {
        public string Glyph;
        readonly MotionAnimator motion;
        bool selected,hover;double selectedAmount,hoverAmount;
        public bool Selected { get { return selected; } set { if(selected==value)return;selected=value;Transition(); } }
        public NavigationButton(){SetStyle(ControlStyles.UserPaint|ControlStyles.OptimizedDoubleBuffer|ControlStyles.AllPaintingInWmPaint,true);FlatStyle=FlatStyle.Flat;FlatAppearance.BorderSize=0;Cursor=Cursors.Hand;Height=46;motion=new MotionAnimator(this);}
        void Transition(){double startSelected=selectedAmount,startHover=hoverAmount,targetSelected=selected?1D:0D,targetHover=hover?1D:0D;motion.Start(170,p=>{selectedAmount=startSelected+(targetSelected-startSelected)*p;hoverAmount=startHover+(targetHover-startHover)*p;Invalidate();});}
        protected override void OnMouseEnter(EventArgs e){hover=true;Transition();base.OnMouseEnter(e);}
        protected override void OnMouseLeave(EventArgs e){hover=false;Transition();base.OnMouseLeave(e);}
        protected override void OnEnabledChanged(EventArgs e){base.OnEnabledChanged(e);Invalidate();}
        protected override void Dispose(bool disposing){if(disposing)motion.Dispose();base.Dispose(disposing);}
        static Color Blend(Color from,Color to,double value){value=Math.Max(0,Math.Min(1,value));return Color.FromArgb((int)(from.R+(to.R-from.R)*value),(int)(from.G+(to.G-from.G)*value),(int)(from.B+(to.B-from.B)*value));}
        static GraphicsPath Round(RectangleF r,float radius){var p=new GraphicsPath();float d=radius*2;p.AddArc(r.Left,r.Top,d,d,180,90);p.AddArc(r.Right-d,r.Top,d,d,270,90);p.AddArc(r.Right-d,r.Bottom-d,d,d,0,90);p.AddArc(r.Left,r.Bottom-d,d,d,90,90);p.CloseFigure();return p;}
        void DrawGlyph(Graphics graphics,Color color)
        {
            using(var pen=new Pen(color,1.6F)){
                pen.StartCap=pen.EndCap=LineCap.Round;pen.LineJoin=LineJoin.Round;float x=18,y=(Height-24)/2F;
                if(Glyph=="USB"){
                    using(var shape=Round(new RectangleF(x+3,y+6,17,17),3))graphics.DrawPath(pen,shape);graphics.DrawRectangle(pen,x+7,y,9,6);graphics.DrawLine(pen,x+10,y+2,x+10,y+4);graphics.DrawLine(pen,x+13,y+2,x+13,y+4);graphics.DrawLine(pen,x+9,y+14,x+15,y+14);
                }else if(Glyph=="TG"){
                    graphics.DrawPolygon(pen,new[]{new PointF(x,y+10),new PointF(x+23,y+1),new PointF(x+18,y+23),new PointF(x+10,y+16)});graphics.DrawLine(pen,x+10,y+16,x+19,y+5);graphics.DrawLine(pen,x+10,y+16,x+8,y+21);
                }else if(Glyph=="A"||Glyph=="iOS"){
                    using(var shape=Round(new RectangleF(x+4,y,15,24),3))graphics.DrawPath(pen,shape);graphics.DrawLine(pen,x+9,y+3,x+14,y+3);graphics.DrawLine(pen,x+10,y+21,x+13,y+21);
                }else if(Glyph=="DIR"){
                    graphics.DrawPolygon(pen,new[]{new PointF(x,y+5),new PointF(x+8,y+5),new PointF(x+11,y+8),new PointF(x+23,y+8),new PointF(x+23,y+22),new PointF(x,y+22)});graphics.DrawLine(pen,x,y+11,x+23,y+11);
                }else using(var font=new Font("Segoe UI",9F,FontStyle.Bold))TextRenderer.DrawText(graphics,Glyph??"",font,new Rectangle(12,0,32,Height),color,TextFormatFlags.VerticalCenter|TextFormatFlags.HorizontalCenter);
            }
        }
        protected override void OnPaint(PaintEventArgs e){
            e.Graphics.SmoothingMode=SmoothingMode.AntiAlias;e.Graphics.Clear(UiTheme.Sidebar);if(Width<18||Height<18)return;Color background=Blend(Blend(UiTheme.Sidebar,Color.FromArgb(34,42,57),hoverAmount),Color.FromArgb(43,54,78),selectedAmount);
            using(var shape=Round(new RectangleF(0,1,Width-1,Height-2),8))using(var brush=new SolidBrush(background))e.Graphics.FillPath(brush,shape);
            if(selectedAmount>0.01D)using(var brush=new SolidBrush(Blend(background,UiTheme.Accent,selectedAmount)))e.Graphics.FillRectangle(brush,0,12,3,Math.Max(1,Height-24));
            Color foreground=Enabled?Blend(Color.FromArgb(181,193,210),Color.White,selectedAmount):UiTheme.Muted;
            DrawGlyph(e.Graphics,Blend(Color.FromArgb(119,139,165),Color.FromArgb(145,178,255),selectedAmount));
            TextRenderer.DrawText(e.Graphics,Text,Font,new Rectangle(50,0,Math.Max(1,Width-54),Height),foreground,TextFormatFlags.VerticalCenter|TextFormatFlags.EndEllipsis);
            if(Focused)ControlPaint.DrawFocusRectangle(e.Graphics,new Rectangle(5,5,Width-10,Height-10));
        }
    }
    public sealed class WorkflowSteps : Control
    {
        readonly MotionAnimator motion;int current;double position;
        public int Current { get { return current; } set { int next=Math.Max(0,Math.Min(2,value));if(current==next)return;current=next;double previous=position;motion.Start(210,p=>{position=previous+(current-previous)*p;Invalidate();}); } }
        public WorkflowSteps(){Height=42;DoubleBuffered=true;motion=new MotionAnimator(this);}
        protected override void Dispose(bool disposing){if(disposing)motion.Dispose();base.Dispose(disposing);}
        protected override void OnPaint(PaintEventArgs e){
            base.OnPaint(e);e.Graphics.SmoothingMode=SmoothingMode.AntiAlias;string[] names={"Источник","Образ и поиск","Проверка файлов"};int width=Math.Max(1,Width/3);
            using(var font=new Font("Segoe UI",9F))for(int i=0;i<3;i++){
                int x=i*width;Color c=i<=Current?UiTheme.Accent:UiTheme.Muted;
                double emphasis=Math.Max(0,1D-Math.Abs(position-i));Color idle=Color.FromArgb(237,241,246),active=Color.FromArgb(224,234,255);Color fill=Color.FromArgb((int)(idle.R+(active.R-idle.R)*emphasis),(int)(idle.G+(active.G-idle.G)*emphasis),(int)(idle.B+(active.B-idle.B)*emphasis));
                using(var b=new SolidBrush(fill))e.Graphics.FillEllipse(b,x,10,24,24);
                TextRenderer.DrawText(e.Graphics,(i+1).ToString(),font,new Rectangle(x,10,24,24),c,TextFormatFlags.HorizontalCenter|TextFormatFlags.VerticalCenter);
                TextRenderer.DrawText(e.Graphics,names[i],font,new Rectangle(x+32,8,Math.Max(30,width-46),28),c,TextFormatFlags.VerticalCenter|TextFormatFlags.EndEllipsis);
            }
        }
    }
}
